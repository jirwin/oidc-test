package models

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/jirwin/oidc-test/internal/crypto"
)

type Issuer struct {
	ID              string
	Name            string
	PrivateKey      string
	PublicKey       string
	KeyID           string
	Scopes          string
	AccessTokenTTL  string // duration string, empty = use global default
	RefreshTokenTTL string
	AuthCodeTTL     string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ParseTTL parses the issuer's TTL override, returning the fallback if empty or invalid.
func ParseTTL(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return d
}

func CreateIssuer(db *sql.DB, name, scopes string) (*Issuer, error) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}

	id, err := randomID()
	if err != nil {
		return nil, err
	}

	if scopes == "" {
		scopes = "openid profile email"
	}

	now := time.Now().UTC()
	_, err = db.Exec(
		`INSERT INTO issuers (id, name, private_key, public_key, key_id, scopes, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, name, kp.PrivateKeyPEM, kp.PublicKeyPEM, kp.KeyID, scopes, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert issuer: %w", err)
	}

	return &Issuer{
		ID:         id,
		Name:       name,
		PrivateKey: kp.PrivateKeyPEM,
		PublicKey:  kp.PublicKeyPEM,
		KeyID:      kp.KeyID,
		Scopes:     scopes,
		CreatedAt:  now,
		UpdatedAt:  now,
	}, nil
}

func GetIssuer(db *sql.DB, id string) (*Issuer, error) {
	iss := &Issuer{}
	err := db.QueryRow(
		`SELECT id, name, private_key, public_key, key_id, scopes, access_token_ttl, refresh_token_ttl, auth_code_ttl, created_at, updated_at FROM issuers WHERE id = ?`, id,
	).Scan(&iss.ID, &iss.Name, &iss.PrivateKey, &iss.PublicKey, &iss.KeyID, &iss.Scopes, &iss.AccessTokenTTL, &iss.RefreshTokenTTL, &iss.AuthCodeTTL, &iss.CreatedAt, &iss.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return iss, nil
}

func ListIssuers(db *sql.DB) ([]*Issuer, error) {
	rows, err := db.Query(`SELECT id, name, scopes, access_token_ttl, refresh_token_ttl, auth_code_ttl, created_at, updated_at FROM issuers ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var issuers []*Issuer
	for rows.Next() {
		iss := &Issuer{}
		if err := rows.Scan(&iss.ID, &iss.Name, &iss.Scopes, &iss.AccessTokenTTL, &iss.RefreshTokenTTL, &iss.AuthCodeTTL, &iss.CreatedAt, &iss.UpdatedAt); err != nil {
			return nil, err
		}
		issuers = append(issuers, iss)
	}
	return issuers, rows.Err()
}

func UpdateIssuer(db *sql.DB, id, name, scopes, accessTokenTTL, refreshTokenTTL, authCodeTTL string) error {
	_, err := db.Exec(
		`UPDATE issuers SET name = ?, scopes = ?, access_token_ttl = ?, refresh_token_ttl = ?, auth_code_ttl = ?, updated_at = ? WHERE id = ?`,
		name, scopes, accessTokenTTL, refreshTokenTTL, authCodeTTL, time.Now().UTC(), id,
	)
	return err
}

func DeleteIssuer(db *sql.DB, id string) error {
	_, err := db.Exec(`DELETE FROM issuers WHERE id = ?`, id)
	return err
}

// GetIssuerByIssuerURL finds an issuer by matching the issuer URL suffix.
func GetIssuerByIssuerURL(db *sql.DB, issuerID string) (*Issuer, error) {
	return GetIssuer(db, issuerID)
}
