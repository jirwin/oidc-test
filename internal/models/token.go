package models

import (
	"database/sql"
	"fmt"
	"time"
)

type Token struct {
	ID        string
	IssuerID  string
	ClientID  string
	Username  string
	Scope     string
	TokenType string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func CreateToken(db *sql.DB, issuerID, clientID, username, scope, tokenType string, expiresAt time.Time) (*Token, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	_, err = db.Exec(
		`INSERT INTO tokens (id, issuer_id, client_id, username, scope, token_type, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, issuerID, clientID, username, scope, tokenType, expiresAt, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert token: %w", err)
	}

	return &Token{
		ID:        id,
		IssuerID:  issuerID,
		ClientID:  clientID,
		Username:  username,
		Scope:     scope,
		TokenType: tokenType,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}, nil
}

func GetToken(db *sql.DB, id string) (*Token, error) {
	t := &Token{}
	err := db.QueryRow(
		`SELECT id, issuer_id, client_id, username, scope, token_type, expires_at, created_at
		 FROM tokens WHERE id = ?`, id,
	).Scan(&t.ID, &t.IssuerID, &t.ClientID, &t.Username, &t.Scope, &t.TokenType, &t.ExpiresAt, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func DeleteTokensByUser(db *sql.DB, issuerID, username string) error {
	_, err := db.Exec(`DELETE FROM tokens WHERE issuer_id = ? AND username = ?`, issuerID, username)
	return err
}
