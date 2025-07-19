package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	// "github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

type OIDCManager struct {
	Provider    *oidc.Provider
	OAuthConfig *oauth2.Config
	Verifier    *oidc.IDTokenVerifier
}

func NewOIDCManager(ctx context.Context) (*OIDCManager, error) {
	issuer := viper.GetString("auth.issuer")
	clientID := viper.GetString("auth.client_id")
	clientSecret := viper.GetString("auth.client_secret")
	redirectURL := viper.GetString("auth.redirect_url")

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get OIDC provider: %w", err)
	}

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	return &OIDCManager{
		Provider:    provider,
		OAuthConfig: oauthConfig,
		Verifier:    verifier,
	}, nil
}

func (m *OIDCManager) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state := generateRandomString(16)
	nonce := generateRandomString(16)

	// Store state and nonce in secure cookies
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_nonce",
		Value:    nonce,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, m.OAuthConfig.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func (m *OIDCManager) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	// Validate state
	originalState, err := r.Cookie("oidc_state")
	if err != nil || originalState.Value != state {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	oauth2Token, err := m.OAuthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusInternalServerError)
		return
	}

	idToken, err := m.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "failed to verify ID token", http.StatusUnauthorized)
		return
	}

	claims := map[string]interface{}{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "failed to parse claims", http.StatusInternalServerError)
		return
	}

	// Store session info in secure cookie (JWT or signed session ID in production)
	cookie := http.Cookie{
		Name:     "session",
		Value:    rawIDToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(1 * time.Hour),
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (m *OIDCManager) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	expiredCookie := http.Cookie{
		Name:     "session",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
	}
	http.SetCookie(w, &expiredCookie)
	http.Redirect(w, r, "/", http.StatusFound)
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
