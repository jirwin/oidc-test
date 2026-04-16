package router

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/jirwin/oidc-test/internal/admin"
	"github.com/jirwin/oidc-test/internal/api"
	"github.com/jirwin/oidc-test/internal/config"
	"github.com/jirwin/oidc-test/internal/middleware"
	"github.com/jirwin/oidc-test/internal/oidc"
)

func New(db *sql.DB, baseURL string, templates map[string]*template.Template, staticFS fs.FS, cfg *config.Config) http.Handler {
	mux := http.NewServeMux()

	// Health check endpoints
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "not ready", "error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})

	// Admin UI
	ah := &admin.Handlers{DB: db, BaseURL: baseURL, Templates: templates}
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	mux.HandleFunc("GET /admin", ah.Dashboard)
	mux.HandleFunc("GET /admin/issuers/new", ah.NewIssuerForm)
	mux.HandleFunc("POST /admin/issuers", ah.CreateIssuer)
	mux.HandleFunc("GET /admin/issuers/{id}", ah.IssuerDetail)
	mux.HandleFunc("GET /admin/issuers/{id}/edit", ah.EditIssuerForm)
	mux.HandleFunc("POST /admin/issuers/{id}", ah.UpdateIssuer)
	mux.HandleFunc("POST /admin/issuers/{id}/delete", ah.DeleteIssuer)
	mux.HandleFunc("GET /admin/issuers/{id}/clients/new", ah.NewClientForm)
	mux.HandleFunc("POST /admin/issuers/{id}/clients", ah.CreateClient)
	mux.HandleFunc("POST /admin/issuers/{id}/clients/{clientId}/delete", ah.DeleteClient)

	// OIDC Discovery & JWKS
	mux.Handle("GET /issuers/{id}/.well-known/openid-configuration", &oidc.DiscoveryHandler{DB: db, BaseURL: baseURL})
	mux.Handle("GET /issuers/{id}/jwks", &oidc.JWKSHandler{DB: db})

	// OAuth2 Authorization Code Flow
	mux.Handle("GET /issuers/{id}/authorize", &oidc.AuthorizeHandler{DB: db, BaseURL: baseURL, Templates: templates})
	mux.Handle("POST /issuers/{id}/authorize", &oidc.AuthorizePostHandler{DB: db, BaseURL: baseURL, Templates: templates})
	mux.Handle("POST /issuers/{id}/consent", &oidc.ConsentHandler{DB: db, BaseURL: baseURL, AuthCodeTTL: cfg.AuthCodeTTL})
	mux.Handle("POST /issuers/{id}/token", &oidc.TokenHandler{DB: db, BaseURL: baseURL, AccessTokenTTL: cfg.AccessTokenTTL, RefreshTokenTTL: cfg.RefreshTokenTTL})

	// OIDC UserInfo
	mux.Handle("GET /issuers/{id}/userinfo", middleware.TokenAuth(db, baseURL, &oidc.UserInfoHandler{DB: db}))
	mux.Handle("POST /issuers/{id}/userinfo", middleware.TokenAuth(db, baseURL, &oidc.UserInfoHandler{DB: db}))

	// RFC 7662 Token Introspection (per-issuer)
	mux.Handle("POST /issuers/{id}/introspect", &oidc.IntrospectHandler{DB: db, BaseURL: baseURL})

	// RP-Initiated Logout
	mux.Handle("GET /issuers/{id}/logout", &oidc.EndSessionHandler{DB: db, BaseURL: baseURL})

	// Legacy API endpoints (token-protected)
	mux.Handle("GET /api/introspect", middleware.TokenAuth(db, baseURL, &api.IntrospectHandler{}))
	mux.Handle("GET /api/admin", middleware.TokenAuth(db, baseURL, &api.AdminHandler{}))

	// Management API
	mgmt := &api.ManagementHandler{DB: db, BaseURL: baseURL, AdminToken: cfg.AdminToken}
	mux.HandleFunc("GET /api/issuers", mgmt.ListIssuers)
	mux.HandleFunc("POST /api/issuers", mgmt.CreateIssuer)
	mux.HandleFunc("GET /api/issuers/{id}", mgmt.GetIssuer)
	mux.HandleFunc("PUT /api/issuers/{id}", mgmt.UpdateIssuer)
	mux.HandleFunc("DELETE /api/issuers/{id}", mgmt.DeleteIssuer)
	mux.HandleFunc("GET /api/issuers/{id}/clients", mgmt.ListClients)
	mux.HandleFunc("POST /api/issuers/{id}/clients", mgmt.CreateClient)
	mux.HandleFunc("DELETE /api/issuers/{id}/clients/{clientId}", mgmt.DeleteClient)
	mux.HandleFunc("GET /api/issuers/{id}/claims", mgmt.ListClaims)
	mux.HandleFunc("POST /api/issuers/{id}/claims", mgmt.CreateClaim)
	mux.HandleFunc("DELETE /api/issuers/{id}/claims/{claimId}", mgmt.DeleteClaim)

	// Static files
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))

	return middleware.CORS(cfg.CORSOrigins, middleware.Logging(mux))
}
