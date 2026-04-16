package oidc

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/jirwin/oidc-test/internal/middleware"
	"github.com/jirwin/oidc-test/internal/models"
)

type UserInfoHandler struct {
	DB *sql.DB
}

func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	username := claims.Subject
	resp := map[string]any{
		"sub":                username,
		"name":               username,
		"preferred_username": username,
		"email":              username + "@test.local",
		"email_verified":     true,
	}

	if hasScope(claims.Scope, "profile") {
		resp["given_name"] = username
		resp["family_name"] = "Testuser"
		resp["locale"] = "en-US"
		resp["updated_at"] = 1700000000
	}

	// Apply custom claims if DB is available
	if h.DB != nil {
		// Extract issuer ID from the issuer URL
		issuerID := r.PathValue("id")
		if issuerID != "" {
			customClaims, err := models.GetCustomClaims(h.DB, issuerID, claims.Audience, username)
			if err == nil {
				for k, v := range customClaims {
					resp[k] = v
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
