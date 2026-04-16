package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/jirwin/oidc-test/internal/models"
)

type ManagementHandler struct {
	DB         *sql.DB
	BaseURL    string
	AdminToken string
}

func (h *ManagementHandler) auth(w http.ResponseWriter, r *http.Request) bool {
	if h.AdminToken == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	if auth == "Bearer "+h.AdminToken {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
	return false
}

func (h *ManagementHandler) ListIssuers(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	issuers, err := models.ListIssuers(h.DB)
	if err != nil {
		writeJSONError(w, "failed to list issuers", http.StatusInternalServerError)
		return
	}
	writeJSON(w, issuers)
}

func (h *ManagementHandler) CreateIssuer(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	var req struct {
		Name   string `json:"name"`
		Scopes string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		writeJSONError(w, "name is required", http.StatusBadRequest)
		return
	}
	issuer, err := models.CreateIssuer(h.DB, req.Name, req.Scopes)
	if err != nil {
		writeJSONError(w, "failed to create issuer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, issuer)
}

func (h *ManagementHandler) GetIssuer(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	id := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, id)
	if err != nil {
		writeJSONError(w, "issuer not found", http.StatusNotFound)
		return
	}
	writeJSON(w, issuer)
}

func (h *ManagementHandler) UpdateIssuer(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	id := r.PathValue("id")
	var req struct {
		Name            string `json:"name"`
		Scopes          string `json:"scopes"`
		AccessTokenTTL  string `json:"access_token_ttl"`
		RefreshTokenTTL string `json:"refresh_token_ttl"`
		AuthCodeTTL     string `json:"auth_code_ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := models.UpdateIssuer(h.DB, id, req.Name, req.Scopes, req.AccessTokenTTL, req.RefreshTokenTTL, req.AuthCodeTTL); err != nil {
		writeJSONError(w, "failed to update issuer", http.StatusInternalServerError)
		return
	}
	issuer, _ := models.GetIssuer(h.DB, id)
	writeJSON(w, issuer)
}

func (h *ManagementHandler) DeleteIssuer(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := models.DeleteIssuer(h.DB, id); err != nil {
		writeJSONError(w, "failed to delete issuer", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ManagementHandler) ListClients(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	issuerID := r.PathValue("id")
	clients, err := models.ListClients(h.DB, issuerID)
	if err != nil {
		writeJSONError(w, "failed to list clients", http.StatusInternalServerError)
		return
	}
	writeJSON(w, clients)
}

func (h *ManagementHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	issuerID := r.PathValue("id")
	var req struct {
		Name        string `json:"name"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.RedirectURI == "" {
		writeJSONError(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	client, err := models.CreateClient(h.DB, issuerID, req.Name, req.RedirectURI)
	if err != nil {
		writeJSONError(w, "failed to create client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, client)
}

func (h *ManagementHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	clientDBID := r.PathValue("clientId")
	if err := models.DeleteClient(h.DB, clientDBID); err != nil {
		writeJSONError(w, "failed to delete client", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ManagementHandler) ListClaims(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	issuerID := r.PathValue("id")
	claims, err := models.ListCustomClaims(h.DB, issuerID)
	if err != nil {
		writeJSONError(w, "failed to list claims", http.StatusInternalServerError)
		return
	}
	writeJSON(w, claims)
}

func (h *ManagementHandler) CreateClaim(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	issuerID := r.PathValue("id")
	var req struct {
		ClientID   string `json:"client_id"`
		Username   string `json:"username"`
		ClaimKey   string `json:"claim_key"`
		ClaimValue string `json:"claim_value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.ClaimKey == "" {
		writeJSONError(w, "claim_key is required", http.StatusBadRequest)
		return
	}
	claim, err := models.CreateCustomClaim(h.DB, issuerID, req.ClientID, req.Username, req.ClaimKey, req.ClaimValue)
	if err != nil {
		writeJSONError(w, "failed to create claim: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, claim)
}

func (h *ManagementHandler) DeleteClaim(w http.ResponseWriter, r *http.Request) {
	if !h.auth(w, r) {
		return
	}
	claimID := r.PathValue("claimId")
	if err := models.DeleteCustomClaim(h.DB, claimID); err != nil {
		writeJSONError(w, "failed to delete claim", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
