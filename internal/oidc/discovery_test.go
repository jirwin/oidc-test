package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jirwin/oidc-test/internal/oidc"
	"github.com/jirwin/oidc-test/internal/testutil"
)

func TestDiscoveryHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)

	handler := &oidc.DiscoveryHandler{DB: db, BaseURL: "http://localhost:8080"}
	r := httptest.NewRequest(http.MethodGet, "/issuers/"+issuer.ID+"/.well-known/openid-configuration", nil)
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var doc map[string]any
	json.NewDecoder(w.Body).Decode(&doc)

	issuerURL := "http://localhost:8080/issuers/" + issuer.ID
	checks := map[string]string{
		"issuer":                 issuerURL,
		"authorization_endpoint": issuerURL + "/authorize",
		"token_endpoint":         issuerURL + "/token",
		"userinfo_endpoint":      issuerURL + "/userinfo",
		"jwks_uri":               issuerURL + "/jwks",
		"introspection_endpoint": issuerURL + "/introspect",
		"end_session_endpoint":   issuerURL + "/logout",
	}
	for k, want := range checks {
		got, _ := doc[k].(string)
		if got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	grantTypes, _ := doc["grant_types_supported"].([]any)
	if len(grantTypes) < 3 {
		t.Errorf("grant_types_supported has %d entries, want >= 3", len(grantTypes))
	}
}

func TestJWKSHandler(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)

	handler := &oidc.JWKSHandler{DB: db}
	r := httptest.NewRequest(http.MethodGet, "/issuers/"+issuer.ID+"/jwks", nil)
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var doc map[string]any
	json.NewDecoder(w.Body).Decode(&doc)

	keys, ok := doc["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("missing or empty keys array")
	}

	key := keys[0].(map[string]any)
	if key["kty"] != "RSA" {
		t.Errorf("kty = %v, want RSA", key["kty"])
	}
	if key["kid"] != issuer.KeyID {
		t.Errorf("kid = %v, want %v", key["kid"], issuer.KeyID)
	}
}
