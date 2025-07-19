package policy

import (
	"errors"
	"net/http"
	"strings"

	"github.com/heyayush09/glyph-proxy/internal/session"
)

var (
	ErrUnauthenticated = errors.New("unauthenticated: login required")
	ErrUnauthorized    = errors.New("unauthorized: access denied")
)

type RoutePolicy struct {
	AllowedUsers  []string `yaml:"allowed_users"`
	AllowedGroups []string `yaml:"allowed_groups"`
}

func (p *RoutePolicy) IsAuthorized(user session.UserClaims) bool {
	if len(p.AllowedUsers) == 0 && len(p.AllowedGroups) == 0 {
		return true // no restrictions
	}

	for _, u := range p.AllowedUsers {
		if strings.EqualFold(u, user.Email) {
			return true
		}
	}

	for _, g := range p.AllowedGroups {
		for _, ug := range user.Groups {
			if strings.EqualFold(g, ug) {
				return true
			}
		}
	}
	return false
}

// Middleware returns an HTTP middleware that checks the route policy
func Middleware(policy RoutePolicy, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := session.GetClaims(r.Context())
		if claims == nil {
			http.Error(w, ErrUnauthenticated.Error(), http.StatusUnauthorized)
			return
		}

		if !policy.IsAuthorized(*claims) {
			http.Error(w, ErrUnauthorized.Error(), http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
