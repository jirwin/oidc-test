package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jirwin/oidc-test/internal/middleware"
)

type AdminHandler struct{}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	scopes := strings.Fields(claims.Scope)
	hasAdmin := false
	for _, s := range scopes {
		if s == "admin" {
			hasAdmin = true
			break
		}
	}

	if !hasAdmin {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "forbidden",
			"message": "admin scope required",
		})
		return
	}

	resp := map[string]any{
		"message": "admin access granted",
		"user":    claims.Subject,
		"scope":   claims.Scope,
		"issuer":  claims.Issuer,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
