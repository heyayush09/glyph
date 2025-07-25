package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/heyayush09/glyph-proxy/internal/config"
	"github.com/heyayush09/glyph-proxy/internal/logging"
	"github.com/heyayush09/glyph-proxy/internal/session"
	"golang.org/x/oauth2"
)

type OIDCManager struct {
	Provider    *oidc.Provider
	OAuthConfig *oauth2.Config
	Verifier    *oidc.IDTokenVerifier
	Config      *config.OIDCConfig
}

type Claims struct {
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`
	Sub           string   `json:"sub"`
}

func NewOIDCManager(ctx context.Context, cfg *config.OIDCConfig) (*OIDCManager, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get OIDC provider: %w", err)
	}

	// Build redirect URL if not specified
	redirectURL := cfg.RedirectURL
	if redirectURL == "" {
		redirectURL = "http://localhost:8080/auth/callback" // Default for development
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &OIDCManager{
		Provider:    provider,
		OAuthConfig: oauthConfig,
		Verifier:    verifier,
		Config:      cfg,
	}, nil
}

func (m *OIDCManager) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state := generateRandomString(32)
	nonce := generateRandomString(32)

	logging.Log.Debug("Login handler initiated, generating state and nonce")

	// Store state and nonce in secure cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})
	logging.Log.Debug("Setting 'oidc_state' cookie")

	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_nonce",
		Value:    nonce,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})
	logging.Log.Debug("Setting 'oidc_nonce' cookie")

	authURL := m.OAuthConfig.AuthCodeURL(state, oidc.Nonce(nonce))
	logging.Log.Debugf("Redirecting to OIDC provider: %s", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (m *OIDCManager) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logging.Log.Debug("Callback handler initiated")

	// Validate state parameter
	state := r.URL.Query().Get("state")
	if state == "" {
		logging.Log.Warn("Callback request missing state parameter")
		http.Error(w, "missing state parameter", http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || stateCookie.Value != state {
		logging.Log.Warnf("Invalid state parameter. Cookie: '%v', Param: '%s'", stateCookie, state)
		http.Error(w, "invalid state parameter", http.StatusBadRequest)
		return
	}
	logging.Log.Debug("State parameter validated successfully")

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		logging.Log.Warn("Callback request missing authorization code")
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}
	logging.Log.Debug("Authorization code received")

	// Exchange code for token
	oauth2Token, err := m.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		logging.Log.Errorf("Token exchange failed: %v", err)
		http.Error(w, fmt.Sprintf("token exchange failed: %v", err), http.StatusInternalServerError)
		return
	}
	logging.Log.Debug("Token exchange successful")

	// Extract ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		logging.Log.Error("No id_token found in token response")
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}
	logging.Log.Debug("ID token extracted")

	// Verify ID token
	idToken, err := m.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		logging.Log.Errorf("Failed to verify ID token: %v", err)
		http.Error(w, fmt.Sprintf("failed to verify ID token: %v", err), http.StatusUnauthorized)
		return
	}
	logging.Log.Debug("ID token verified successfully")

	// Parse claims
	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		logging.Log.Errorf("Failed to parse claims from ID token: %v", err)
		http.Error(w, fmt.Sprintf("failed to parse claims: %v", err), http.StatusInternalServerError)
		return
	}
	logging.Log.Debugf("Claims parsed successfully: Email=%s, Name=%s, Groups=%v", claims.Email, claims.Name, claims.Groups)

	// Create session data matching your session format
	sessionData := map[string]string{
		"email":    claims.Email,
		"name":     claims.Name,
		"sub":      claims.Sub,
		"groups":   strings.Join(claims.Groups, ","),
		"expires":  fmt.Sprintf("%d", time.Now().Add(6*time.Hour).Unix()),
	}

	// Determine if the cookie should be secure
	secureCookie := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	logging.Log.Debugf("Setting cookies with Secure=%t", secureCookie)

	// Set session cookie using your session manager
	if err := session.SetSession(w, sessionData, secureCookie); err != nil {
		logging.Log.Errorf("Failed to create session: %v", err)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	// Set refresh token if available
	if oauth2Token.RefreshToken != "" {
		if err := session.SetRefreshToken(w, oauth2Token.RefreshToken, secureCookie); err != nil {
			// Log error but don't fail the login
			logging.Log.Warnf("Failed to set refresh token: %v", err)
		}
	}

	// Clear temporary cookies
	clearTempCookies(w, r.TLS != nil)

	// Redirect to original destination or home
	redirectTo := r.URL.Query().Get("redirect")
	if redirectTo == "" {
		redirectTo = "/"
	}
	
	http.Redirect(w, r, redirectTo, http.StatusFound)
}

func (m *OIDCManager) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session.ClearSession(w)
	clearTempCookies(w, r.TLS != nil)
	
	// Optionally redirect to OIDC provider logout
	logoutURL := r.URL.Query().Get("logout_url")
	if logoutURL == "" {
		logoutURL = "/"
	}
	
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

// Middleware to protect routes that require authentication
func (m *OIDCManager) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.Log.Debugf("RequireAuth middleware processing request for %s", r.URL.Path)

		// Skip auth for auth endpoints and health checks
		if isPublicEndpoint(r.URL.Path) {
			logging.Log.Debugf("Path %s is public, skipping auth", r.URL.Path)
			next.ServeHTTP(w, r)
			return
		}

		// Check if user has valid session
		claims, err := session.GetSession(r)
		if err != nil {
			logging.Log.Infof("No valid session found for %s, redirecting to login. Error: %v", r.URL.Path, err)
			// Redirect to login with return URL
			redirectToLogin(w, r)
			return
		}

		logging.Log.Debugf("User authenticated with claims for user: %s", claims.Email)
		next.ServeHTTP(w, r)
	})
}

func isPublicEndpoint(path string) bool {
	publicPaths := []string{
		"/auth/login",
		"/auth/callback", 
		"/auth/logout",
		"/health",
		"/metrics",
	}
	
	for _, publicPath := range publicPaths {
		if path == publicPath {
			return true
		}
	}
	return false
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	loginURL := "/auth/login"
	if r.URL.Path != "/" {
		loginURL += "?redirect=" + r.URL.Path
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func clearTempCookies(w http.ResponseWriter, secure bool) {
	expiredCookie := &http.Cookie{
		HttpOnly: true,
		Secure:   secure,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	}

	stateCookie := *expiredCookie
	stateCookie.Name = "oidc_state"
	http.SetCookie(w, &stateCookie)

	nonceCookie := *expiredCookie
	nonceCookie.Name = "oidc_nonce"
	http.SetCookie(w, &nonceCookie)
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based randomness if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}
