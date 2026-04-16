package oidc

import (
	"database/sql"
	"html/template"
	"net/http"
	"strings"

	"github.com/jirwin/oidc-test/internal/models"
)

type AuthorizeHandler struct {
	DB        *sql.DB
	BaseURL   string
	Templates map[string]*template.Template
}

func renderTemplate(w http.ResponseWriter, templates map[string]*template.Template, name string, data any) {
	t, ok := templates[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

// ServeHTTP handles GET /issuers/{id}/authorize — validates params and shows login form.
func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, issuerID)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}

	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")

	if responseType != "code" {
		http.Error(w, "unsupported response_type, must be 'code'", http.StatusBadRequest)
		return
	}

	client, err := models.GetClientByClientID(h.DB, issuer.ID, clientID)
	if err != nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}

	if redirectURI != client.RedirectURI {
		http.Error(w, "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	if scope == "" {
		scope = issuer.Scopes
	}

	data := map[string]any{
		"IssuerID":            issuer.ID,
		"IssuerName":          issuer.Name,
		"ClientName":          client.Name,
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"Scope":               scope,
		"State":               state,
		"Nonce":               nonce,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
	}

	renderTemplate(w, h.Templates, "login.html", data)
}

type AuthorizePostHandler struct {
	DB        *sql.DB
	BaseURL   string
	Templates map[string]*template.Template
}

// ServeHTTP handles POST /issuers/{id}/authorize — processes login, shows consent.
func (h *AuthorizePostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, issuerID)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}

	r.ParseForm()
	username := r.FormValue("username")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	if username == "" {
		http.Error(w, "username is required", http.StatusBadRequest)
		return
	}

	// Determine scopes based on username
	isAdmin := strings.HasPrefix(strings.ToLower(username), "admin")
	scopeList := strings.Fields(scope)
	if isAdmin {
		hasAdmin := false
		for _, s := range scopeList {
			if s == "admin" {
				hasAdmin = true
				break
			}
		}
		if !hasAdmin {
			scopeList = append(scopeList, "admin")
		}
	}
	finalScope := strings.Join(scopeList, " ")

	client, err := models.GetClientByClientID(h.DB, issuer.ID, clientID)
	if err != nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}

	data := map[string]any{
		"IssuerID":            issuer.ID,
		"IssuerName":          issuer.Name,
		"ClientName":          client.Name,
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"Scope":               finalScope,
		"Scopes":              strings.Fields(finalScope),
		"State":               state,
		"Nonce":               nonce,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
		"Username":            username,
		"IsAdmin":             isAdmin,
	}

	renderTemplate(w, h.Templates, "consent.html", data)
}
