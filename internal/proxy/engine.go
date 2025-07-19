package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/heyayush09/glyph-proxy/internal/config"
	"github.com/heyayush09/glyph-proxy/internal/session"
)

type Engine struct {
	Config *config.AtomicConfig
}

func New(cfg *config.AtomicConfig) *Engine {
	return &Engine{Config: cfg}
}

func (e *Engine) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentCfg := e.Config.Load()

		var targetURL string
		host := r.Host
		route, ok := currentCfg.Routes[host]
		if !ok {
			http.Error(w, "Route not found", http.StatusNotFound)
			return
		}

		switch {
		case route.To != "":
			targetURL = route.To
		case route.Target.Type == "ip":
			targetURL = "http://" + route.Target.IP
		default:
			http.Error(w, "Invalid route config", http.StatusBadGateway)
			return
		}

		u, err := url.Parse(targetURL)
		if err != nil {
			http.Error(w, "Bad target URL", http.StatusBadGateway)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(u)

		// Inject X-User-* headers if session present
		proxy.ModifyResponse = func(resp *http.Response) error {
			return nil
		}
		r.Header.Del("X-User-Email")
		r.Header.Del("X-User-Name")

		if claims, ok := r.Context().Value(session.ClaimsKey()).(*session.UserClaims); ok {
			r.Header.Set("X-User-Email", claims.Email)
			r.Header.Set("X-User-Name", claims.Name)
		}

		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[proxy] error: %v", err)
			http.Error(w, "Proxy error", http.StatusBadGateway)
		}

		// Proxy request
		proxy.ServeHTTP(w, r)
	})
}
