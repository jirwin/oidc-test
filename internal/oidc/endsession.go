package oidc

import (
	"database/sql"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jirwin/oidc-test/internal/crypto"
	"github.com/jirwin/oidc-test/internal/models"
)

type EndSessionHandler struct {
	DB      *sql.DB
	BaseURL string
}

func (h *EndSessionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, issuerID)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}

	idTokenHint := r.URL.Query().Get("id_token_hint")
	postLogoutRedirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	state := r.URL.Query().Get("state")

	// If id_token_hint is provided, validate it and revoke associated tokens
	if idTokenHint != "" {
		pub, err := crypto.ParsePublicKey(issuer.PublicKey)
		if err == nil {
			claims := jwt.MapClaims{}
			_, err = jwt.ParseWithClaims(idTokenHint, claims, func(t *jwt.Token) (any, error) {
				return pub, nil
			}, jwt.WithValidMethods([]string{"RS256"}))
			if err == nil {
				if sub, ok := claims["sub"].(string); ok {
					models.DeleteTokensByUser(h.DB, issuer.ID, sub)
				}
			}
		}
	}

	if postLogoutRedirectURI != "" {
		u, err := url.Parse(postLogoutRedirectURI)
		if err == nil {
			if state != "" {
				q := u.Query()
				q.Set("state", state)
				u.RawQuery = q.Encode()
			}
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}

	// Default: redirect to admin dashboard
	http.Redirect(w, r, "/admin", http.StatusFound)
}
