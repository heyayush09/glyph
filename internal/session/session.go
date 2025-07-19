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

func SetSession(w http.ResponseWriter, claims map[string]string) error {
	data := ""
	for k, v := range claims {
		data += k + "=" + v + ";"
	}
	encrypted, err := encrypt([]byte(data))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    base64.StdEncoding.EncodeToString(encrypted),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(cookieDuration.Seconds()),
	})
	return nil
}

func SetRefreshToken(w http.ResponseWriter, token string) error {
	encrypted, err := encrypt([]byte(token))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     refreshName,
		Value:    base64.StdEncoding.EncodeToString(encrypted),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(refreshDuration.Seconds()),
	})
	return nil
}

func GetSession(r *http.Request) (map[string]string, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, err
	}
	cipherText, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, err
	}
	plain, err := decrypt(cipherText)
	if err != nil {
		return nil, err
	}
	pairs := strings.Split(string(plain), ";")
	claims := make(map[string]string)
	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			claims[parts[0]] = parts[1]
		}
	}
	return claims, nil
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
		claims, err := GetSession(r)
		if err == nil {
			r = r.WithContext(context.WithValue(r.Context(), claimsKey, claims))
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
