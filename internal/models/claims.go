package models

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type CustomClaim struct {
	ID         string
	IssuerID   string
	ClientID   string // empty = issuer-level
	Username   string // empty = all users
	ClaimKey   string
	ClaimValue string // JSON-encoded
	CreatedAt  time.Time
}

func CreateCustomClaim(db *sql.DB, issuerID, clientID, username, claimKey, claimValue string) (*CustomClaim, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	_, err = db.Exec(
		`INSERT INTO custom_claims (id, issuer_id, client_id, username, claim_key, claim_value, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, issuerID, clientID, username, claimKey, claimValue, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert custom claim: %w", err)
	}

	return &CustomClaim{
		ID:         id,
		IssuerID:   issuerID,
		ClientID:   clientID,
		Username:   username,
		ClaimKey:   claimKey,
		ClaimValue: claimValue,
		CreatedAt:  now,
	}, nil
}

func ListCustomClaims(db *sql.DB, issuerID string) ([]*CustomClaim, error) {
	rows, err := db.Query(
		`SELECT id, issuer_id, client_id, username, claim_key, claim_value, created_at
		 FROM custom_claims WHERE issuer_id = ? ORDER BY created_at DESC`, issuerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var claims []*CustomClaim
	for rows.Next() {
		c := &CustomClaim{}
		if err := rows.Scan(&c.ID, &c.IssuerID, &c.ClientID, &c.Username, &c.ClaimKey, &c.ClaimValue, &c.CreatedAt); err != nil {
			return nil, err
		}
		claims = append(claims, c)
	}
	return claims, rows.Err()
}

func DeleteCustomClaim(db *sql.DB, id string) error {
	_, err := db.Exec(`DELETE FROM custom_claims WHERE id = ?`, id)
	return err
}

// GetCustomClaims returns merged custom claims for the given context.
// Priority: issuer-level < client-level < user-level.
func GetCustomClaims(db *sql.DB, issuerID, clientID, username string) (map[string]any, error) {
	rows, err := db.Query(
		`SELECT client_id, username, claim_key, claim_value FROM custom_claims
		 WHERE issuer_id = ?
		   AND (client_id = '' OR client_id = ?)
		   AND (username = '' OR username = ?)
		 ORDER BY
		   CASE WHEN client_id = '' AND username = '' THEN 0
		        WHEN client_id != '' AND username = '' THEN 1
		        ELSE 2 END`,
		issuerID, clientID, username,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]any)
	for rows.Next() {
		var cID, uname, key, value string
		if err := rows.Scan(&cID, &uname, &key, &value); err != nil {
			return nil, err
		}
		var parsed any
		if err := json.Unmarshal([]byte(value), &parsed); err != nil {
			parsed = value // use raw string if not valid JSON
		}
		result[key] = parsed
	}
	return result, rows.Err()
}
