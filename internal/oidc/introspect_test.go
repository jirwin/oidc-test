package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jirwin/oidc-test/internal/crypto"
	"github.com/jirwin/oidc-test/internal/models"
	"github.com/jirwin/oidc-test/internal/oidc"
	"github.com/jirwin/oidc-test/internal/testutil"
)

func TestIntrospectHandler_ActiveToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)
	client := testutil.CreateTestClient(t, db, issuer.ID)
	baseURL := "http://localhost:8080"

	// Create a token record and sign a JWT
	issuerURL := baseURL + "/issuers/" + issuer.ID
	tokenRecord, err := models.CreateToken(db, issuer.ID, client.ClientID, "testuser", "openid", "access_token", time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("CreateToken() error: %v", err)
	}

	claims := oidc.BuildAccessTokenClaims(issuerURL, "testuser", client.ClientID, tokenRecord.ID, "openid", "testuser", "test@test.local", time.Hour)
	tokenStr, err := crypto.SignJWT(claims, issuer.PrivateKey, issuer.KeyID)
	if err != nil {
		t.Fatalf("SignJWT() error: %v", err)
	}

	handler := &oidc.IntrospectHandler{DB: db, BaseURL: baseURL}
	form := url.Values{"token": {tokenStr}}
	r := httptest.NewRequest(http.MethodPost, "/issuers/"+issuer.ID+"/introspect", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(client.ClientID, client.ClientSecret)
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["active"] != true {
		t.Errorf("active = %v, want true", resp["active"])
	}
	if resp["sub"] != "testuser" {
		t.Errorf("sub = %v, want testuser", resp["sub"])
	}
}

func TestIntrospectHandler_InvalidToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)
	client := testutil.CreateTestClient(t, db, issuer.ID)

	handler := &oidc.IntrospectHandler{DB: db, BaseURL: "http://localhost:8080"}
	form := url.Values{"token": {"not-a-valid-token"}}
	r := httptest.NewRequest(http.MethodPost, "/issuers/"+issuer.ID+"/introspect", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(client.ClientID, client.ClientSecret)
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["active"] != false {
		t.Errorf("active = %v, want false", resp["active"])
	}
}

func TestIntrospectHandler_BadClientAuth(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)

	handler := &oidc.IntrospectHandler{DB: db, BaseURL: "http://localhost:8080"}
	form := url.Values{"token": {"whatever"}}
	r := httptest.NewRequest(http.MethodPost, "/issuers/"+issuer.ID+"/introspect", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("bad", "bad")
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
