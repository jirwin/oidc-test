package oidc

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/jirwin/oidc-test/internal/models"
)

type ConsentHandler struct {
	DB          *sql.DB
	BaseURL     string
	AuthCodeTTL time.Duration
}

// ServeHTTP handles POST /issuers/{id}/consent -- issues auth code and redirects.
func (h *ConsentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, issuerID)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}

	r.ParseForm()
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	username := r.FormValue("username")

	authCodeTTL := models.ParseTTL(issuer.AuthCodeTTL, h.AuthCodeTTL)
	ac, err := models.CreateAuthCode(h.DB, issuerID, clientID, redirectURI, username, scope, nonce, codeChallenge, codeChallengeMethod, authCodeTTL)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create auth code: %v", err), http.StatusInternalServerError)
		return
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	q := u.Query()
	q.Set("code", ac.Code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}
