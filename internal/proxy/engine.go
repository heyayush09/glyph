package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/heyayush09/glyph-proxy/internal/config"
	"github.com/heyayush09/glyph-proxy/internal/logging"
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

		// Get the route for this host
		host := r.Host
		logging.Log.Debugf("Proxy engine received request for host: %s", host)
		route, ok := currentCfg.Routes[host]
		if !ok {
			logging.Log.Warnf("Route not found for host: %s", host)
			http.Error(w, "Route not found", http.StatusNotFound)
			return
		}
		logging.Log.Debugf("Found matching route for host %s: %+v", host, route)

		// Determine target URL based on route configuration
		targetURL, err := e.resolveTargetURL(route)
		if err != nil {
			logging.Log.Errorf("[proxy] failed to resolve target URL for host %s: %v", host, err)
			http.Error(w, "Invalid route configuration", http.StatusBadGateway)
			return
		}
		logging.Log.Debugf("Resolved target URL: %s", targetURL)

		// Parse target URL
		u, err := url.Parse(targetURL)
		if err != nil {
			logging.Log.Errorf("[proxy] invalid target URL %s: %v", targetURL, err)
			http.Error(w, "Bad target URL", http.StatusBadGateway)
			return
		}

		// Create reverse proxy
		proxy := httputil.NewSingleHostReverseProxy(u)

		// Configure proxy behavior
		e.configureProxy(proxy, route)

		// Modify request before proxying
		e.modifyRequest(r)

		// Proxy the request
		proxy.ServeHTTP(w, r)
	})
}

func (e *Engine) resolveTargetURL(route config.Route) (string, error) {
	// If 'to' field is specified, use it directly
	if route.To != "" {
		return route.To, nil
	}

	// Otherwise, construct URL from target configuration
	switch route.Target.Type {
	case "ip":
		if route.Target.IP == "" {
			return "", fmt.Errorf("IP is required when target type is 'ip'")
		}
		scheme := "http"
		if route.Target.Port == 443 {
			scheme = "https"
		}
		if route.Target.Port != 0 && route.Target.Port != 80 && route.Target.Port != 443 {
			return fmt.Sprintf("%s://%s:%d", scheme, route.Target.IP, route.Target.Port), nil
		}
		return fmt.Sprintf("%s://%s", scheme, route.Target.IP), nil

	case "url":
		if route.Target.URL == "" {
			return "", fmt.Errorf("URL is required when target type is 'url'")
		}
		return route.Target.URL, nil

	case "service":
		// For service discovery or other service types
		// This could be extended to support service discovery mechanisms
		return "", fmt.Errorf("service type not yet implemented")

	default:
		return "", fmt.Errorf("unsupported target type: %s", route.Target.Type)
	}
}

func (e *Engine) configureProxy(proxy *httputil.ReverseProxy, route config.Route) {
	// Set up error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logging.Log.Errorf("[proxy] error proxying request to %s: %v", r.URL.String(), err)
		http.Error(w, "Proxy error", http.StatusBadGateway)
	}

	// Configure request director for path manipulation
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		
		// Handle path stripping if configured
		if route.StripPath {
			e.stripPath(req)
		}
	}

	// Configure response modification if needed
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Add any response modifications here if needed
		return nil
	}
}

func (e *Engine) modifyRequest(r *http.Request) {
	// Clear any existing user headers to prevent header injection
	r.Header.Del("X-User-Email")
	r.Header.Del("X-User-Name")
	r.Header.Del("X-User-Groups")

	// Extract session claims and inject user information headers
	if claims, err := session.GetSession(r); err == nil && claims != nil {
		logging.Log.Debugf("Injecting user claims into headers for user: %s", claims.Email)
		if claims.Email != "" {
			r.Header.Set("X-User-Email", claims.Email)
		}
		if claims.Name != "" {
			r.Header.Set("X-User-Name", claims.Name)
		}
		if len(claims.Groups) > 0 {
			r.Header.Set("X-User-Groups", strings.Join(claims.Groups, ","))
		}
	} else {
		logging.Log.Debug("No session claims found to inject into headers")
	}

	// Set additional proxy headers
	r.Header.Set("X-Forwarded-Proto", e.getScheme(r))
	r.Header.Set("X-Forwarded-Host", r.Host)
	
	// Preserve original IP if not already set
	if r.Header.Get("X-Forwarded-For") == "" {
		if clientIP := e.getClientIP(r); clientIP != "" {
			r.Header.Set("X-Forwarded-For", clientIP)
		}
	}
}

func (e *Engine) stripPath(r *http.Request) {
	// Remove the first path segment
	// For example: /app/api/users -> /api/users
	path := r.URL.Path
	if path != "/" {
		segments := strings.Split(path, "/")
		if len(segments) > 2 {
			r.URL.Path = "/" + strings.Join(segments[2:], "/")
		} else {
			r.URL.Path = "/"
		}
	}
}

func (e *Engine) getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}

func (e *Engine) getClientIP(r *http.Request) string {
	// Check for IP in various headers (in order of preference)
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, get the first one
		if ips := strings.Split(forwarded, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	// Fall back to RemoteAddr (format: "IP:port")
	if ip := strings.Split(r.RemoteAddr, ":"); len(ip) > 0 {
		return ip[0]
	}
	return ""
}
