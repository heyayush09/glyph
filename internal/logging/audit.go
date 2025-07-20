package logging

import (
	"log"
	"net/http"
	"time"
)

type AuditLog struct {
	Time       time.Time
	Method     string
	Path       string
	StatusCode int
	UserEmail  string
	RemoteIP   string
}

func LogRequest(r *http.Request, statusCode int, userEmail string) {
	entry := AuditLog{
		Time:       time.Now(),
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: statusCode,
		UserEmail:  userEmail,
		RemoteIP:   r.RemoteAddr,
	}
	log.Printf("AUDIT | %s | %s | %d | %s | %s", entry.Time.Format(time.RFC3339), entry.Method, entry.StatusCode, entry.UserEmail, entry.Path)
}

// Middleware to wrap handlers
func AuditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(rw, r)

		user := r.Context().Value("claims")
		email := "anonymous"
		if userClaims, ok := user.(map[string]interface{}); ok {
			if e, ok := userClaims["email"].(string); ok {
				email = e
			}
		}

		LogRequest(r, rw.statusCode, email)
	})
}

// Helper to capture status codes

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
