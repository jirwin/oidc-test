package admin

import (
	"database/sql"
	"html/template"
	"net/http"

	"github.com/jirwin/oidc-test/internal/models"
)

type Handlers struct {
	DB        *sql.DB
	BaseURL   string
	Templates map[string]*template.Template
}

func (h *Handlers) render(w http.ResponseWriter, name string, data any) {
	t, ok := h.Templates[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}

func (h *Handlers) Dashboard(w http.ResponseWriter, r *http.Request) {
	issuers, err := models.ListIssuers(h.DB)
	if err != nil {
		http.Error(w, "failed to list issuers", http.StatusInternalServerError)
		return
	}
	h.render(w, "dashboard.html", map[string]any{
		"Issuers": issuers,
		"BaseURL": h.BaseURL,
	})
}

func (h *Handlers) NewIssuerForm(w http.ResponseWriter, r *http.Request) {
	h.render(w, "issuer_form.html", map[string]any{
		"IsNew": true,
	})
}

func (h *Handlers) CreateIssuer(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := r.FormValue("name")
	scopes := r.FormValue("scopes")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	issuer, err := models.CreateIssuer(h.DB, name, scopes)
	if err != nil {
		http.Error(w, "failed to create issuer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Apply TTLs if provided
	accessTTL := r.FormValue("access_token_ttl")
	refreshTTL := r.FormValue("refresh_token_ttl")
	authCodeTTL := r.FormValue("auth_code_ttl")
	if accessTTL != "" || refreshTTL != "" || authCodeTTL != "" {
		models.UpdateIssuer(h.DB, issuer.ID, name, issuer.Scopes, accessTTL, refreshTTL, authCodeTTL)
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handlers) IssuerDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, id)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}
	clients, err := models.ListClients(h.DB, id)
	if err != nil {
		http.Error(w, "failed to list clients", http.StatusInternalServerError)
		return
	}
	h.render(w, "issuer_detail.html", map[string]any{
		"Issuer":    issuer,
		"Clients":   clients,
		"BaseURL":   h.BaseURL,
		"IssuerURL": h.BaseURL + "/issuers/" + issuer.ID,
	})
}

func (h *Handlers) EditIssuerForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, id)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}
	h.render(w, "issuer_form.html", map[string]any{
		"IsNew":  false,
		"Issuer": issuer,
	})
}

func (h *Handlers) UpdateIssuer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	r.ParseForm()
	name := r.FormValue("name")
	scopes := r.FormValue("scopes")
	accessTTL := r.FormValue("access_token_ttl")
	refreshTTL := r.FormValue("refresh_token_ttl")
	authCodeTTL := r.FormValue("auth_code_ttl")
	if err := models.UpdateIssuer(h.DB, id, name, scopes, accessTTL, refreshTTL, authCodeTTL); err != nil {
		http.Error(w, "failed to update issuer", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/issuers/"+id, http.StatusSeeOther)
}

func (h *Handlers) DeleteIssuer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := models.DeleteIssuer(h.DB, id); err != nil {
		http.Error(w, "failed to delete issuer", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *Handlers) NewClientForm(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, issuerID)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}
	h.render(w, "client_form.html", map[string]any{
		"Issuer": issuer,
	})
}

func (h *Handlers) CreateClient(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	r.ParseForm()
	name := r.FormValue("name")
	redirectURI := r.FormValue("redirect_uri")
	if redirectURI == "" {
		http.Error(w, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	_, err := models.CreateClient(h.DB, issuerID, name, redirectURI)
	if err != nil {
		http.Error(w, "failed to create client: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/issuers/"+issuerID, http.StatusSeeOther)
}

func (h *Handlers) DeleteClient(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	clientDBID := r.PathValue("clientId")
	if err := models.DeleteClient(h.DB, clientDBID); err != nil {
		http.Error(w, "failed to delete client", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/issuers/"+issuerID, http.StatusSeeOther)
}
