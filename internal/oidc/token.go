package oidc

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jirwin/oidc-test/internal/crypto"
	"github.com/jirwin/oidc-test/internal/models"
)

type TokenHandler struct {
	DB              *sql.DB
	BaseURL         string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
}

// resolveAccessTTL returns the issuer's override if set, otherwise the global default.
func (h *TokenHandler) resolveAccessTTL(issuer *models.Issuer) time.Duration {
	return models.ParseTTL(issuer.AccessTokenTTL, h.AccessTokenTTL)
}

func (h *TokenHandler) resolveRefreshTTL(issuer *models.Issuer) time.Duration {
	return models.ParseTTL(issuer.RefreshTokenTTL, h.RefreshTokenTTL)
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	issuerID := r.PathValue("id")
	issuer, err := models.GetIssuer(h.DB, issuerID)
	if err != nil {
		http.Error(w, "issuer not found", http.StatusNotFound)
		return
	}

	r.ParseForm()
	grantType := r.FormValue("grant_type")

	clientID, clientSecret := clientCredentials(r)

	client, err := models.GetClientByClientID(h.DB, issuer.ID, clientID)
	if err != nil {
		jsonError(w, "invalid_client", "unknown client", http.StatusUnauthorized)
		return
	}

	if client.ClientSecret != clientSecret {
		jsonError(w, "invalid_client", "bad client secret", http.StatusUnauthorized)
		return
	}

	switch grantType {
	case "authorization_code":
		h.handleAuthCodeExchange(w, r, issuer, client)
	case "refresh_token":
		h.handleRefreshToken(w, r, issuer, client)
	case "client_credentials":
		h.handleClientCredentials(w, r, issuer, client)
	default:
		jsonError(w, "unsupported_grant_type", "supported: authorization_code, refresh_token, client_credentials", http.StatusBadRequest)
	}
}

func (h *TokenHandler) handleAuthCodeExchange(w http.ResponseWriter, r *http.Request, issuer *models.Issuer, client *models.Client) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	ac, err := models.GetAuthCode(h.DB, code)
	if err != nil {
		jsonError(w, "invalid_grant", "unknown authorization code", http.StatusBadRequest)
		return
	}

	if ac.Used {
		jsonError(w, "invalid_grant", "authorization code already used", http.StatusBadRequest)
		return
	}

	if time.Now().UTC().After(ac.ExpiresAt) {
		jsonError(w, "invalid_grant", "authorization code expired", http.StatusBadRequest)
		return
	}

	if ac.IssuerID != issuer.ID {
		jsonError(w, "invalid_grant", "code not issued by this issuer", http.StatusBadRequest)
		return
	}

	if ac.ClientID != client.ClientID {
		jsonError(w, "invalid_grant", "client_id mismatch", http.StatusBadRequest)
		return
	}

	if ac.RedirectURI != redirectURI {
		jsonError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		return
	}

	// PKCE validation
	if ac.CodeChallenge != "" {
		if codeVerifier == "" {
			jsonError(w, "invalid_grant", "code_verifier required", http.StatusBadRequest)
			return
		}
		if !verifyPKCE(ac.CodeChallenge, ac.CodeChallengeMethod, codeVerifier) {
			jsonError(w, "invalid_grant", "PKCE verification failed", http.StatusBadRequest)
			return
		}
	}

	models.MarkAuthCodeUsed(h.DB, code)

	resp, err := h.issueTokens(issuer, client.ClientID, ac.Username, ac.Scope)
	if err != nil {
		jsonError(w, "server_error", err.Error(), http.StatusInternalServerError)
		return
	}

	// Only include id_token when openid scope was requested
	if hasScope(ac.Scope, "openid") {
		issuerURL := h.BaseURL + "/issuers/" + issuer.ID
		email := ac.Username + "@test.local"
		idClaims := BuildIDTokenClaims(issuerURL, ac.Username, client.ClientID, ac.Nonce, ac.Username, email, h.resolveAccessTTL(issuer))
		idToken, err := crypto.SignJWT(idClaims, issuer.PrivateKey, issuer.KeyID)
		if err != nil {
			jsonError(w, "server_error", "failed to sign ID token", http.StatusInternalServerError)
			return
		}
		resp["id_token"] = idToken
	}

	writeTokenResponse(w, resp)
}

func (h *TokenHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request, issuer *models.Issuer, client *models.Client) {
	refreshTokenStr := r.FormValue("refresh_token")
	if refreshTokenStr == "" {
		jsonError(w, "invalid_request", "refresh_token is required", http.StatusBadRequest)
		return
	}

	pub, err := crypto.ParsePublicKey(issuer.PublicKey)
	if err != nil {
		jsonError(w, "server_error", "internal error", http.StatusInternalServerError)
		return
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(refreshTokenStr, claims, func(t *jwt.Token) (any, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		jsonError(w, "invalid_grant", "invalid refresh token", http.StatusBadRequest)
		return
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		jsonError(w, "invalid_grant", "refresh token missing jti", http.StatusBadRequest)
		return
	}

	rt, err := models.GetToken(h.DB, jti)
	if err != nil {
		jsonError(w, "invalid_grant", "unknown refresh token", http.StatusBadRequest)
		return
	}

	if rt.TokenType != "refresh_token" {
		jsonError(w, "invalid_grant", "token is not a refresh token", http.StatusBadRequest)
		return
	}

	if rt.ClientID != client.ClientID {
		jsonError(w, "invalid_grant", "client_id mismatch", http.StatusBadRequest)
		return
	}

	scope := r.FormValue("scope")
	if scope == "" {
		scope = rt.Scope
	}

	resp, err := h.issueTokens(issuer, client.ClientID, rt.Username, scope)
	if err != nil {
		jsonError(w, "server_error", err.Error(), http.StatusInternalServerError)
		return
	}

	writeTokenResponse(w, resp)
}

func (h *TokenHandler) handleClientCredentials(w http.ResponseWriter, r *http.Request, issuer *models.Issuer, client *models.Client) {
	scope := r.FormValue("scope")
	if scope == "" {
		scope = issuer.Scopes
	}

	issuerURL := h.BaseURL + "/issuers/" + issuer.ID
	accessTTL := h.resolveAccessTTL(issuer)
	atExpiry := time.Now().UTC().Add(accessTTL)
	atRecord, err := models.CreateToken(h.DB, issuer.ID, client.ClientID, client.ClientID, scope, "access_token", atExpiry)
	if err != nil {
		jsonError(w, "server_error", "failed to create access token", http.StatusInternalServerError)
		return
	}

	atClaims := BuildAccessTokenClaims(issuerURL, client.ClientID, client.ClientID, atRecord.ID, scope, client.Name, "", accessTTL)
	accessToken, err := crypto.SignJWT(atClaims, issuer.PrivateKey, issuer.KeyID)
	if err != nil {
		jsonError(w, "server_error", "failed to sign access token", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(accessTTL.Seconds()),
		"scope":        scope,
	}

	writeTokenResponse(w, resp)
}

func (h *TokenHandler) issueTokens(issuer *models.Issuer, clientID, username, scope string) (map[string]any, error) {
	issuerURL := h.BaseURL + "/issuers/" + issuer.ID
	email := username + "@test.local"
	accessTTL := h.resolveAccessTTL(issuer)
	refreshTTL := h.resolveRefreshTTL(issuer)

	atExpiry := time.Now().UTC().Add(accessTTL)
	atRecord, err := models.CreateToken(h.DB, issuer.ID, clientID, username, scope, "access_token", atExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	atClaims := BuildAccessTokenClaims(issuerURL, username, clientID, atRecord.ID, scope, username, email, accessTTL)
	accessToken, err := crypto.SignJWT(atClaims, issuer.PrivateKey, issuer.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	rtExpiry := time.Now().UTC().Add(refreshTTL)
	rtRecord, err := models.CreateToken(h.DB, issuer.ID, clientID, username, scope, "refresh_token", rtExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	rtClaims := BuildRefreshTokenClaims(issuerURL, username, clientID, rtRecord.ID, scope, refreshTTL)
	refreshToken, err := crypto.SignJWT(rtClaims, issuer.PrivateKey, issuer.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
		"refresh_token": refreshToken,
		"scope":         scope,
	}, nil
}

func writeTokenResponse(w http.ResponseWriter, resp map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

func clientCredentials(r *http.Request) (clientID, clientSecret string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

func verifyPKCE(challenge, method, verifier string) bool {
	switch strings.ToUpper(method) {
	case "S256", "":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	case "PLAIN":
		return verifier == challenge
	default:
		return false
	}
}

func hasScope(scopeStr, target string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == target {
			return true
		}
	}
	return false
}

func jsonError(w http.ResponseWriter, errCode, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": description,
	})
}
