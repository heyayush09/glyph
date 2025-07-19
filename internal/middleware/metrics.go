package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/heyayush09/glyph-proxy/internal/session"
)

// MetricsHandler provides a basic metrics endpoint
func MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# Basic metrics endpoint\n# TODO: Implement proper metrics\n"))
	})
}

// Logging middleware for request logging
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer wrapper to capture status
		rw := &responseWriter{ResponseWriter: w, statusCode: 200}
		
		// Process request
		next.ServeHTTP(rw, r)
		
		// Log request details
		duration := time.Since(start)
		userEmail := getUserEmail(r)
		
		fmt.Printf("[%s] %s %s %d %v user=%s\n", 
			start.Format("2006-01-02 15:04:05"),
			r.Method, 
			r.URL.Path, 
			rw.statusCode, 
			duration,
			userEmail,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func getUserEmail(r *http.Request) string {
	claims := session.GetClaims(r.Context())
	if claims == nil {
		return "anonymous"
	}
	return claims.Email
}