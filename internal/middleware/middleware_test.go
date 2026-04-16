package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jirwin/oidc-test/internal/crypto"
	"github.com/jirwin/oidc-test/internal/middleware"
	"github.com/jirwin/oidc-test/internal/oidc"
	"github.com/jirwin/oidc-test/internal/testutil"
)

func TestTokenAuth_ValidToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	issuer := testutil.CreateTestIssuer(t, db)
	baseURL := "http://localhost:8080"

	issuerURL := baseURL + "/issuers/" + issuer.ID
	claims := oidc.BuildAccessTokenClaims(issuerURL, "testuser", "client1", "jti1", "openid", "testuser", "test@test.local", time.Hour)
	tokenStr, err := crypto.SignJWT(claims, issuer.PrivateKey, issuer.KeyID)
	if err != nil {
		t.Fatalf("SignJWT() error: %v", err)
	}

	var gotClaims *middleware.Claims
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = middleware.GetClaims(r)
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.TokenAuth(db, baseURL, inner)
	r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	r.Header.Set("Authorization", "Bearer "+tokenStr)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if gotClaims == nil {
		t.Fatal("claims are nil")
	}
	if gotClaims.Subject != "testuser" {
		t.Errorf("subject = %q, want testuser", gotClaims.Subject)
	}
}

func TestTokenAuth_MissingToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := middleware.TokenAuth(db, "http://localhost:8080", inner)
	r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestTokenAuth_InvalidToken(t *testing.T) {
	db := testutil.SetupTestDB(t)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called")
	})

	handler := middleware.TokenAuth(db, "http://localhost:8080", inner)
	r := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	r.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
