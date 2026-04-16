package crypto

import (
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	if !strings.HasPrefix(kp.PrivateKeyPEM, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("private key PEM has wrong prefix")
	}
	if !strings.HasPrefix(kp.PublicKeyPEM, "-----BEGIN RSA PUBLIC KEY-----") {
		t.Error("public key PEM has wrong prefix")
	}
	if kp.KeyID == "" {
		t.Error("key ID is empty")
	}
}

func TestParsePrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	priv, err := ParsePrivateKey(kp.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error: %v", err)
	}
	if priv.N.BitLen() < 2048 {
		t.Errorf("key size = %d bits, want >= 2048", priv.N.BitLen())
	}
}

func TestParsePublicKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	pub, err := ParsePublicKey(kp.PublicKeyPEM)
	if err != nil {
		t.Fatalf("ParsePublicKey() error: %v", err)
	}
	if pub.N.BitLen() < 2048 {
		t.Errorf("key size = %d bits, want >= 2048", pub.N.BitLen())
	}
}

func TestPublicKeyToJWK(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}
	pub, _ := ParsePublicKey(kp.PublicKeyPEM)
	jwk := PublicKeyToJWK(pub, kp.KeyID)

	if jwk.Kty != "RSA" {
		t.Errorf("kty = %q, want RSA", jwk.Kty)
	}
	if jwk.Use != "sig" {
		t.Errorf("use = %q, want sig", jwk.Use)
	}
	if jwk.Alg != "RS256" {
		t.Errorf("alg = %q, want RS256", jwk.Alg)
	}
	if jwk.Kid != kp.KeyID {
		t.Errorf("kid = %q, want %q", jwk.Kid, kp.KeyID)
	}
	if jwk.N == "" {
		t.Error("N is empty")
	}
	if jwk.E == "" {
		t.Error("E is empty")
	}
}

func TestSignJWT(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	claims := jwt.MapClaims{"sub": "testuser", "iss": "test"}
	tokenStr, err := SignJWT(claims, kp.PrivateKeyPEM, kp.KeyID)
	if err != nil {
		t.Fatalf("SignJWT() error: %v", err)
	}

	// Parse and verify
	pub, _ := ParsePublicKey(kp.PublicKeyPEM)
	parsed := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, parsed, func(t *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("ParseWithClaims() error: %v", err)
	}
	if !token.Valid {
		t.Error("token is not valid")
	}
	if parsed["sub"] != "testuser" {
		t.Errorf("sub = %v, want testuser", parsed["sub"])
	}
	if token.Header["kid"] != kp.KeyID {
		t.Errorf("kid = %v, want %v", token.Header["kid"], kp.KeyID)
	}
}

func TestSignJWT_InvalidKey(t *testing.T) {
	_, err := SignJWT(jwt.MapClaims{}, "not-a-pem", "kid")
	if err == nil {
		t.Error("expected error for invalid key")
	}
}
