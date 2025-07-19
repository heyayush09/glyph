package middleware

import (
	"net/http"

	"github.com/heyayush09/glyph-proxy/internal/monitoring"
)

func WithMetrics(next http.Handler, routeName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		monitoring.RecordRequest(routeName)
		next.ServeHTTP(w, r)
	})
}
