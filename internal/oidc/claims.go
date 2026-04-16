package oidc

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func BuildAccessTokenClaims(issuerURL, sub, aud, jti, scope, name, email string, expiresIn time.Duration) jwt.MapClaims {
	now := time.Now().UTC()
	return jwt.MapClaims{
		"iss":   issuerURL,
		"sub":   sub,
		"aud":   aud,
		"exp":   jwt.NewNumericDate(now.Add(expiresIn)),
		"iat":   jwt.NewNumericDate(now),
		"jti":   jti,
		"scope": scope,
		"name":  name,
		"email": email,
	}
}

func BuildIDTokenClaims(issuerURL, sub, aud, nonce, name, email string, expiresIn time.Duration) jwt.MapClaims {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   issuerURL,
		"sub":   sub,
		"aud":   aud,
		"exp":   jwt.NewNumericDate(now.Add(expiresIn)),
		"iat":   jwt.NewNumericDate(now),
		"name":  name,
		"email": email,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return claims
}

func BuildRefreshTokenClaims(issuerURL, sub, aud, jti, scope string, expiresIn time.Duration) jwt.MapClaims {
	now := time.Now().UTC()
	return jwt.MapClaims{
		"iss":        issuerURL,
		"sub":        sub,
		"aud":        aud,
		"exp":        jwt.NewNumericDate(now.Add(expiresIn)),
		"iat":        jwt.NewNumericDate(now),
		"jti":        jti,
		"scope":      scope,
		"token_type": "refresh_token",
	}
}

// MergeCustomClaims adds custom claims to an existing claims map.
// Reserved OIDC claims (iss, sub, aud, exp, iat, jti) cannot be overridden.
func MergeCustomClaims(claims jwt.MapClaims, custom map[string]any) {
	reserved := map[string]bool{
		"iss": true, "sub": true, "aud": true,
		"exp": true, "iat": true, "jti": true,
	}
	for k, v := range custom {
		if !reserved[k] {
			claims[k] = v
		}
	}
}
