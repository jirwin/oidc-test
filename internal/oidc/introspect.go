package oidc

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jirwin/oidc-test/internal/crypto"
	"github.com/jirwin/oidc-test/internal/models"
)

// IntrospectHandler implements RFC 7662 Token Introspection.
type IntrospectHandler struct {
	DB      *sql.DB
	BaseURL string
}

func (h *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, issuerID)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}

	// Authenticate the calling client
	cID, cSecret := clientCredentials(r)
	client, err := models.GetClientByClientID(h.DB, issuer.ID, cID)
	if err != nil || client.ClientSecret != cSecret {
		jsonError(w, "invalid_client", "client authentication failed", http.StatusUnauthorized)
		return
	}

	r.ParseForm()
	tokenStr := r.FormValue("token")
	if tokenStr == "" {
		inactive(w)
		return
	}

	// Parse and verify the token
	pub, err := crypto.ParsePublicKey(issuer.PublicKey)
	if err != nil {
		inactive(w)
		return
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		inactive(w)
		return
	}

	jti, _ := claims["jti"].(string)
	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	scope, _ := claims["scope"].(string)
	tokenType, _ := claims["token_type"].(string)
	if tokenType == "" {
		tokenType = "access_token"
	}

	// Verify token exists in DB
	if jti != "" {
		if _, err := models.GetToken(h.DB, jti); err != nil {
			inactive(w)
			return
		}
	}

	issuerURL := h.BaseURL + "/issuers/" + issuer.ID
	resp := map[string]any{
		"active":     true,
		"sub":        sub,
		"iss":        issuerURL,
		"aud":        aud,
		"scope":      scope,
		"client_id":  cID,
		"token_type": tokenType,
	}

	if exp, ok := claims["exp"]; ok {
		resp["exp"] = exp
	}
	if iat, ok := claims["iat"]; ok {
		resp["iat"] = iat
	}
	if name, ok := claims["name"]; ok {
		resp["username"] = name
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func inactive(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"active": false})
}
