package oidc

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestBuildAccessTokenClaims(t *testing.T) {
	claims := BuildAccessTokenClaims("https://example.com", "user1", "client1", "jti1", "openid profile", "User One", "user1@test.local", time.Hour)

	checks := map[string]string{
		"iss":   "https://example.com",
		"sub":   "user1",
		"aud":   "client1",
		"jti":   "jti1",
		"scope": "openid profile",
		"name":  "User One",
		"email": "user1@test.local",
	}
	for k, want := range checks {
		got, _ := claims[k].(string)
		if got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if claims["exp"] == nil {
		t.Error("exp is nil")
	}
	if claims["iat"] == nil {
		t.Error("iat is nil")
	}
}

func TestBuildIDTokenClaims_WithNonce(t *testing.T) {
	claims := BuildIDTokenClaims("https://example.com", "user1", "client1", "nonce123", "User One", "user1@test.local", time.Hour)
	if claims["nonce"] != "nonce123" {
		t.Errorf("nonce = %v, want nonce123", claims["nonce"])
	}
}

func TestBuildIDTokenClaims_WithoutNonce(t *testing.T) {
	claims := BuildIDTokenClaims("https://example.com", "user1", "client1", "", "User One", "user1@test.local", time.Hour)
	if _, ok := claims["nonce"]; ok {
		t.Error("nonce should not be present when empty")
	}
}

func TestBuildRefreshTokenClaims(t *testing.T) {
	claims := BuildRefreshTokenClaims("https://example.com", "user1", "client1", "jti1", "openid", 30*24*time.Hour)
	if claims["token_type"] != "refresh_token" {
		t.Errorf("token_type = %v, want refresh_token", claims["token_type"])
	}
}

func TestMergeCustomClaims(t *testing.T) {
	claims := jwt.MapClaims{
		"iss": "original",
		"sub": "original",
	}
	custom := map[string]any{
		"iss":        "should-not-override",
		"sub":        "should-not-override",
		"department": "engineering",
		"role":       "admin",
	}
	MergeCustomClaims(claims, custom)

	if claims["iss"] != "original" {
		t.Error("iss was overridden")
	}
	if claims["sub"] != "original" {
		t.Error("sub was overridden")
	}
	if claims["department"] != "engineering" {
		t.Errorf("department = %v, want engineering", claims["department"])
	}
	if claims["role"] != "admin" {
		t.Errorf("role = %v, want admin", claims["role"])
	}
}
