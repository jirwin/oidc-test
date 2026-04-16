package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jirwin/oidc-test/internal/oidc"
	"github.com/jirwin/oidc-test/internal/testutil"
)

func TestTokenHandler_AuthCodeExchange(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)
	client := testutil.CreateTestClient(t, db, issuer.ID)
	ac := testutil.CreateTestAuthCode(t, db, issuer.ID, client.ClientID, client.RedirectURI, "testuser", "openid profile")

	handler := &oidc.TokenHandler{
		DB:              db,
		BaseURL:         "http://localhost:8080",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {ac.Code},
		"redirect_uri": {client.RedirectURI},
		"client_id":    {client.ClientID},
		"client_secret": {client.ClientSecret},
	}

	r := httptest.NewRequest(http.MethodPost, "/issuers/"+issuer.ID+"/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["access_token"] == nil {
		t.Error("missing access_token")
	}
	if resp["refresh_token"] == nil {
		t.Error("missing refresh_token")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}
	if resp["id_token"] == nil {
		t.Error("missing id_token (openid scope was requested)")
	}
}

func TestTokenHandler_AuthCodeUsedTwice(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)
	client := testutil.CreateTestClient(t, db, issuer.ID)
	ac := testutil.CreateTestAuthCode(t, db, issuer.ID, client.ClientID, client.RedirectURI, "testuser", "openid")

	handler := &oidc.TokenHandler{
		DB:              db,
		BaseURL:         "http://localhost:8080",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {ac.Code},
		"redirect_uri": {client.RedirectURI},
		"client_id":    {client.ClientID},
		"client_secret": {client.ClientSecret},
	}

	// First exchange succeeds
	r := httptest.NewRequest(http.MethodPost, "/issuers/"+issuer.ID+"/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("first exchange: status = %d, want 200", w.Code)
	}

	// Second exchange fails
	r2 := httptest.NewRequest(http.MethodPost, "/issuers/"+issuer.ID+"/token", strings.NewReader(form.Encode()))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r2.SetPathValue("id", issuer.ID)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("second exchange: status = %d, want 400", w2.Code)
	}
}

func TestTokenHandler_ClientCredentials(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)
	client := testutil.CreateTestClient(t, db, issuer.ID)

	handler := &oidc.TokenHandler{
		DB:              db,
		BaseURL:         "http://localhost:8080",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	form := url.Values{
		"grant_type":   {"client_credentials"},
		"client_id":    {client.ClientID},
		"client_secret": {client.ClientSecret},
		"scope":        {"openid"},
	}

	r := httptest.NewRequest(http.MethodPost, "/issuers/"+issuer.ID+"/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["access_token"] == nil {
		t.Error("missing access_token")
	}
	if resp["refresh_token"] != nil {
		t.Error("client_credentials should not return refresh_token")
	}
}

func TestTokenHandler_InvalidClient(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)

	handler := &oidc.TokenHandler{
		DB:              db,
		BaseURL:         "http://localhost:8080",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}

	form := url.Values{
		"grant_type":   {"client_credentials"},
		"client_id":    {"nonexistent"},
		"client_secret": {"wrong"},
	}

	r := httptest.NewRequest(http.MethodPost, "/issuers/"+issuer.ID+"/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("id", issuer.ID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
