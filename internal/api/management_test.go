package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jirwin/oidc-test/internal/api"
	"github.com/jirwin/oidc-test/internal/testutil"
)

func TestManagement_CreateAndListIssuers(t *testing.T) {
	db := testutil.SetupTestDB(t)
	h := &api.ManagementHandler{DB: db, BaseURL: "http://localhost:8080"}

	// Create
	body := `{"name":"test-issuer","scopes":"openid profile"}`
	r := httptest.NewRequest(http.MethodPost, "/api/issuers", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.CreateIssuer(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201; body: %s", w.Code, w.Body.String())
	}

	// List
	r2 := httptest.NewRequest(http.MethodGet, "/api/issuers", nil)
	w2 := httptest.NewRecorder()
	h.ListIssuers(w2, r2)

	if w2.Code != http.StatusOK {
		t.Fatalf("list: status = %d, want 200", w2.Code)
	}

	var issuers []map[string]any
	json.NewDecoder(w2.Body).Decode(&issuers)
	if len(issuers) != 1 {
		t.Errorf("got %d issuers, want 1", len(issuers))
	}
}

func TestManagement_CreateAndListClients(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)
	h := &api.ManagementHandler{DB: db, BaseURL: "http://localhost:8080"}

	// Create client
	body := `{"name":"my-app","redirect_uri":"http://localhost:3000/callback"}`
	r := httptest.NewRequest(http.MethodPost, "/api/issuers/"+issuer.ID+"/clients", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()
	h.CreateClient(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("create client: status = %d, want 201; body: %s", w.Code, w.Body.String())
	}

	// List clients
	r2 := httptest.NewRequest(http.MethodGet, "/api/issuers/"+issuer.ID+"/clients", nil)
	r2.SetPathValue("id", issuer.ID)
	w2 := httptest.NewRecorder()
	h.ListClients(w2, r2)

	var clients []map[string]any
	json.NewDecoder(w2.Body).Decode(&clients)
	if len(clients) != 1 {
		t.Errorf("got %d clients, want 1", len(clients))
	}
}

func TestManagement_AdminTokenAuth(t *testing.T) {
	db := testutil.SetupTestDB(t)
	h := &api.ManagementHandler{DB: db, BaseURL: "http://localhost:8080", AdminToken: "secret123"}

	// Without token
	r := httptest.NewRequest(http.MethodGet, "/api/issuers", nil)
	w := httptest.NewRecorder()
	h.ListIssuers(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: status = %d, want 401", w.Code)
	}

	// With wrong token
	r2 := httptest.NewRequest(http.MethodGet, "/api/issuers", nil)
	r2.Header.Set("Authorization", "Bearer wrong")
	w2 := httptest.NewRecorder()
	h.ListIssuers(w2, r2)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", w2.Code)
	}

	// With correct token
	r3 := httptest.NewRequest(http.MethodGet, "/api/issuers", nil)
	r3.Header.Set("Authorization", "Bearer secret123")
	w3 := httptest.NewRecorder()
	h.ListIssuers(w3, r3)
	if w3.Code != http.StatusOK {
		t.Errorf("correct token: status = %d, want 200", w3.Code)
	}
}

func TestManagement_CustomClaims(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)
	h := &api.ManagementHandler{DB: db, BaseURL: "http://localhost:8080"}

	// Create claim
	body := `{"claim_key":"department","claim_value":"\"engineering\""}`
	r := httptest.NewRequest(http.MethodPost, "/api/issuers/"+issuer.ID+"/claims", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()
	h.CreateClaim(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("create claim: status = %d, want 201; body: %s", w.Code, w.Body.String())
	}

	// List claims
	r2 := httptest.NewRequest(http.MethodGet, "/api/issuers/"+issuer.ID+"/claims", nil)
	r2.SetPathValue("id", issuer.ID)
	w2 := httptest.NewRecorder()
	h.ListClaims(w2, r2)

	var claims []map[string]any
	json.NewDecoder(w2.Body).Decode(&claims)
	if len(claims) != 1 {
		t.Errorf("got %d claims, want 1", len(claims))
	}
}
