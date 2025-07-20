package session

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/heyayush09/glyph-proxy/internal/logging"
)

const (
	cookieName     = "glyph_session"
	refreshName    = "glyph_refresh"
	cookieDuration = 6 * time.Hour
	refreshDuration = 7 * 24 * time.Hour // 7 days
)

var (
	encryptionKey []byte
)

type UserClaims struct {
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
}

func InitSessionStore() error {
	key := os.Getenv("GLYPH_SESSION_KEY")
	if key == "" {
		return errors.New("GLYPH_SESSION_KEY is not set")
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return errors.New("GLYPH_SESSION_KEY must be 32 bytes base64 encoded")
	}
	encryptionKey = decoded
	return nil
}

func SetSession(w http.ResponseWriter, claims map[string]string, secure bool) error {
	data := ""
	for k, v := range claims {
		data += k + "=" + v + ";"
	}
	encrypted, err := encrypt([]byte(data))
	if err != nil {
		logging.Log.Errorf("Failed to encrypt session data: %v", err)
		return err
	}

	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    base64.StdEncoding.EncodeToString(encrypted),
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(cookieDuration.Seconds()),
	}

	http.SetCookie(w, cookie)
	logging.Log.Debugf("Setting session cookie: %s with Secure=%t", cookie.Name, secure)
	return nil
}

func SetRefreshToken(w http.ResponseWriter, token string, secure bool) error {
	encrypted, err := encrypt([]byte(token))
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     refreshName,
		Value:    base64.StdEncoding.EncodeToString(encrypted),
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(refreshDuration.Seconds()),
	}

	http.SetCookie(w, cookie)
	logging.Log.Debugf("Setting refresh token cookie with Secure=%t", secure)
	return nil
}

func GetSession(r *http.Request) (*UserClaims, error) {
	logging.Log.Debugf("Attempting to get session cookie '%s'", cookieName)
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		logging.Log.Debugf("Session cookie not found: %v", err)
		return nil, err
	}

	logging.Log.Debug("Session cookie found, attempting to decrypt")
	cipherText, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		logging.Log.Warnf("Failed to base64 decode session cookie: %v", err)
		return nil, err
	}

	plain, err := decrypt(cipherText)
	if err != nil {
		logging.Log.Warnf("Failed to decrypt session cookie: %v", err)
		return nil, err
	}

	// Parse the key-value pairs from the decrypted string
	pairs := strings.Split(string(plain), ";")
	claimsMap := make(map[string]string)
	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			claimsMap[parts[0]] = parts[1]
		}
	}

	// Convert map to UserClaims struct
	userClaims := &UserClaims{
		Email:  claimsMap["email"],
		Name:   claimsMap["name"],
		Groups: strings.Split(claimsMap["groups"], ","),
	}

	if userClaims.Email == "" {
		return nil, errors.New("email claim is missing from session")
	}

	logging.Log.Debugf("Successfully decrypted session claims for user: %s", userClaims.Email)
	return userClaims, nil
}

func GetRefreshToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(refreshName)
	if err != nil {
		return "", err
	}
	cipherText, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", err
	}
	plain, err := decrypt(cipherText)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     refreshName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

type contextKey string

const claimsKey contextKey = "claims"

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logging.Log.Debugf("Session middleware processing request for %s", r.URL.Path)
		userClaims, err := GetSession(r)
		if err == nil && userClaims != nil {
			logging.Log.Debugf("Session claims found for user %s, adding to request context", userClaims.Email)
			ctx := context.WithValue(r.Context(), claimsKey, userClaims)
			r = r.WithContext(ctx)
		} else {
			logging.Log.Debug("No valid session found for request")
		}
		next.ServeHTTP(w, r)
	})
}

func GetClaims(ctx context.Context) *UserClaims {
	claims, ok := ctx.Value(claimsKey).(*UserClaims)
	if !ok {
		return nil
	}
	return claims
}

// --- Encryption helpers ---

func encrypt(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	return ciphertext, nil
}

func decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("invalid ciphertext")
	}
	nonce, cipherText := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}
