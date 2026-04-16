package models

import (
	"database/sql"
	"fmt"
	"time"
)

type Client struct {
	ID           string
	IssuerID     string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Name         string
	CreatedAt    time.Time
}

func CreateClient(db *sql.DB, issuerID, name, redirectURI string) (*Client, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	clientID, err := randomID()
	if err != nil {
		return nil, err
	}
	clientSecret, err := randomSecret()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	_, err = db.Exec(
		`INSERT INTO clients (id, issuer_id, client_id, client_secret, redirect_uri, name, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, issuerID, clientID, clientSecret, redirectURI, name, now,
	)
	if err != nil {
		return nil, fmt.Errorf("insert client: %w", err)
	}

	return &Client{
		ID:           id,
		IssuerID:     issuerID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Name:         name,
		CreatedAt:    now,
	}, nil
}

func GetClientByClientID(db *sql.DB, issuerID, clientID string) (*Client, error) {
	c := &Client{}
	err := db.QueryRow(
		`SELECT id, issuer_id, client_id, client_secret, redirect_uri, name, created_at
		 FROM clients WHERE issuer_id = ? AND client_id = ?`, issuerID, clientID,
	).Scan(&c.ID, &c.IssuerID, &c.ClientID, &c.ClientSecret, &c.RedirectURI, &c.Name, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func ListClients(db *sql.DB, issuerID string) ([]*Client, error) {
	rows, err := db.Query(
		`SELECT id, issuer_id, client_id, client_secret, redirect_uri, name, created_at
		 FROM clients WHERE issuer_id = ? ORDER BY created_at DESC`, issuerID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*Client
	for rows.Next() {
		c := &Client{}
		if err := rows.Scan(&c.ID, &c.IssuerID, &c.ClientID, &c.ClientSecret, &c.RedirectURI, &c.Name, &c.CreatedAt); err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func DeleteClient(db *sql.DB, id string) error {
	_, err := db.Exec(`DELETE FROM clients WHERE id = ?`, id)
	return err
}
