package oidc

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jirwin/oidc-test/internal/models"
)

type DiscoveryHandler struct {
	DB      *sql.DB
	BaseURL string
}

func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, issuerID)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}

	issuerURL := h.BaseURL + "/issuers/" + issuer.ID

	scopes := strings.Fields(issuer.Scopes)
	for _, required := range []string{"admin", "offline_access"} {
		found := false
		for _, s := range scopes {
			if s == required {
				found = true
				break
			}
		}
		if !found {
			scopes = append(scopes, required)
		}
	}

	doc := map[string]any{
		"issuer":                                issuerURL,
		"authorization_endpoint":                issuerURL + "/authorize",
		"token_endpoint":                        issuerURL + "/token",
		"userinfo_endpoint":                     issuerURL + "/userinfo",
		"jwks_uri":                              issuerURL + "/jwks",
		"introspection_endpoint":                issuerURL + "/introspect",
		"end_session_endpoint":                  issuerURL + "/logout",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      scopes,
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nonce", "name", "email", "scope"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}
