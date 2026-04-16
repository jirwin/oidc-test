package models

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

type AuthCode struct {
	Code                string
	IssuerID            string
	ClientID            string
	RedirectURI         string
	Username            string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	Used                bool
	CreatedAt           time.Time
}

func CreateAuthCode(db *sql.DB, issuerID, clientID, redirectURI, username, scope, nonce, codeChallenge, codeChallengeMethod string, ttl time.Duration) (*AuthCode, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generate auth code: %w", err)
	}
	code := hex.EncodeToString(b)

	expiresAt := time.Now().UTC().Add(ttl)
	_, err := db.Exec(
		`INSERT INTO auth_codes (code, issuer_id, client_id, redirect_uri, username, scope, nonce, code_challenge, code_challenge_method, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		code, issuerID, clientID, redirectURI, username, scope, nonce, codeChallenge, codeChallengeMethod, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert auth code: %w", err)
	}

	return &AuthCode{
		Code:                code,
		IssuerID:            issuerID,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Username:            username,
		Scope:               scope,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           expiresAt,
	}, nil
}

func GetAuthCode(db *sql.DB, code string) (*AuthCode, error) {
	ac := &AuthCode{}
	var used int
	err := db.QueryRow(
		`SELECT code, issuer_id, client_id, redirect_uri, username, scope, nonce, code_challenge, code_challenge_method, expires_at, used, created_at
		 FROM auth_codes WHERE code = ?`, code,
	).Scan(&ac.Code, &ac.IssuerID, &ac.ClientID, &ac.RedirectURI, &ac.Username, &ac.Scope, &ac.Nonce,
		&ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.ExpiresAt, &used, &ac.CreatedAt)
	if err != nil {
		return nil, err
	}
	ac.Used = used != 0
	return ac, nil
}

func MarkAuthCodeUsed(db *sql.DB, code string) error {
	_, err := db.Exec(`UPDATE auth_codes SET used = 1 WHERE code = ?`, code)
	return err
}
