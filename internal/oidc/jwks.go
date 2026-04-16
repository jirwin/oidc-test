package oidc

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/jirwin/oidc-test/internal/crypto"
	"github.com/jirwin/oidc-test/internal/models"
)

type JWKSHandler struct {
	DB *sql.DB
}

func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, issuerID)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}

	pub, err := crypto.ParsePublicKey(issuer.PublicKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	jwk := crypto.PublicKeyToJWK(pub, issuer.KeyID)

	doc := map[string]any{
		"keys": []crypto.JWK{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}
