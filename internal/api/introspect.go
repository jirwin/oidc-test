package api

import (
	"encoding/json"
	"net/http"

	"github.com/jirwin/oidc-test/internal/middleware"
)

type IntrospectHandler struct{}

func (h *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	resp := map[string]any{
		"active":   true,
		"sub":      claims.Subject,
		"iss":      claims.Issuer,
		"aud":      claims.Audience,
		"scope":    claims.Scope,
		"name":     claims.Name,
		"email":    claims.Email,
		"token_id": claims.JTI,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
