package middleware

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jirwin/oidc-test/internal/crypto"
	"github.com/jirwin/oidc-test/internal/models"
)

type contextKey string

const ClaimsKey contextKey = "claims"

type Claims struct {
	Issuer   string
	Subject  string
	Audience string
	Scope    string
	Name     string
	Email    string
	JTI      string
}

func TokenAuth(db *sql.DB, baseURL string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")

		// Parse without validation to extract issuer
		parser := jwt.NewParser(jwt.WithoutClaimsValidation())
		unverified := jwt.MapClaims{}
		_, _, err := parser.ParseUnverified(tokenStr, unverified)
		if err != nil {
			http.Error(w, `{"error":"invalid token format"}`, http.StatusUnauthorized)
			return
		}

		iss, _ := unverified["iss"].(string)
		if iss == "" {
			http.Error(w, `{"error":"missing issuer claim"}`, http.StatusUnauthorized)
			return
		}

		// Extract issuer ID from URL: {baseURL}/issuers/{id}
		prefix := baseURL + "/issuers/"
		if !strings.HasPrefix(iss, prefix) {
			http.Error(w, `{"error":"unknown issuer"}`, http.StatusUnauthorized)
			return
		}
		issuerID := strings.TrimPrefix(iss, prefix)

		issuer, err := models.GetIssuer(db, issuerID)
		if err != nil {
			http.Error(w, `{"error":"unknown issuer"}`, http.StatusUnauthorized)
			return
		}

		pub, err := crypto.ParsePublicKey(issuer.PublicKey)
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}

		// Now verify the token properly
		verified := jwt.MapClaims{}
		_, err = jwt.ParseWithClaims(tokenStr, verified, func(t *jwt.Token) (any, error) {
			return pub, nil
		}, jwt.WithValidMethods([]string{"RS256"}))
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		claims := Claims{
			Issuer:   getStr(verified, "iss"),
			Subject:  getStr(verified, "sub"),
			Audience: getStr(verified, "aud"),
			Scope:    getStr(verified, "scope"),
			Name:     getStr(verified, "name"),
			Email:    getStr(verified, "email"),
			JTI:      getStr(verified, "jti"),
		}

		ctx := context.WithValue(r.Context(), ClaimsKey, &claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetClaims(r *http.Request) *Claims {
	claims, _ := r.Context().Value(ClaimsKey).(*Claims)
	return claims
}

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func getStr(m jwt.MapClaims, key string) string {
	v, _ := m[key].(string)
	return v
}
