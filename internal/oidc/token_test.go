package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifyPKCE_S256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if !verifyPKCE(challenge, "S256", verifier) {
		t.Error("S256 PKCE verification should pass")
	}
}

func TestVerifyPKCE_Plain(t *testing.T) {
	verifier := "plainverifier"
	if !verifyPKCE(verifier, "PLAIN", verifier) {
		t.Error("plain PKCE verification should pass")
	}
}

func TestVerifyPKCE_InvalidVerifier(t *testing.T) {
	h := sha256.Sum256([]byte("correct"))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if verifyPKCE(challenge, "S256", "wrong") {
		t.Error("PKCE verification should fail with wrong verifier")
	}
}

func TestVerifyPKCE_UnknownMethod(t *testing.T) {
	if verifyPKCE("challenge", "UNKNOWN", "verifier") {
		t.Error("PKCE verification should fail with unknown method")
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		scope  string
		target string
		want   bool
	}{
		{"openid profile email", "openid", true},
		{"openid profile email", "profile", true},
		{"openid profile email", "admin", false},
		{"", "openid", false},
		{"openid", "openid", true},
	}
	for _, tt := range tests {
		got := hasScope(tt.scope, tt.target)
		if got != tt.want {
			t.Errorf("hasScope(%q, %q) = %v, want %v", tt.scope, tt.target, got, tt.want)
		}
	}
}

func TestClientCredentials_BasicAuth(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.SetBasicAuth("myclient", "mysecret")
	id, secret := clientCredentials(r)
	if id != "myclient" || secret != "mysecret" {
		t.Errorf("got (%q, %q), want (myclient, mysecret)", id, secret)
	}
}

func TestClientCredentials_PostBody(t *testing.T) {
	body := "client_id=myclient&client_secret=mysecret"
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()
	id, secret := clientCredentials(r)
	if id != "myclient" || secret != "mysecret" {
		t.Errorf("got (%q, %q), want (myclient, mysecret)", id, secret)
	}
}
