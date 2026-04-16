package testutil

import (
	"database/sql"
	"testing"
	"time"

	"github.com/jirwin/oidc-test/internal/db"
	"github.com/jirwin/oidc-test/internal/models"
)

func SetupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func CreateTestIssuer(t *testing.T, database *sql.DB) *models.Issuer {
	t.Helper()
	issuer, err := models.CreateIssuer(database, "test-issuer", "openid profile email")
	if err != nil {
		t.Fatalf("failed to create test issuer: %v", err)
	}
	return issuer
}

func CreateTestClient(t *testing.T, database *sql.DB, issuerID string) *models.Client {
	t.Helper()
	client, err := models.CreateClient(database, issuerID, "test-client", "http://localhost:3000/callback")
	if err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}
	return client
}

func CreateTestAuthCode(t *testing.T, database *sql.DB, issuerID, clientID, redirectURI, username, scope string) *models.AuthCode {
	t.Helper()
	ac, err := models.CreateAuthCode(database, issuerID, clientID, redirectURI, username, scope, "", "", "", 10*time.Minute)
	if err != nil {
		t.Fatalf("failed to create test auth code: %v", err)
	}
	return ac
}
