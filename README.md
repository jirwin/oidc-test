# oidc-test

A lightweight OIDC/OAuth2 test provider for development and CI. Create multiple test issuers and clients through a web admin UI or REST API, then run standard OpenID Connect flows against them.

## Features

- Authorization code flow with PKCE (S256 and plain)
- Client credentials grant
- RS256 JWT signing with per-issuer key pairs
- Refresh token support
- RFC 7662 token introspection
- RP-Initiated Logout
- Configurable custom claims per issuer, client, or user
- Multi-issuer support with isolated key material
- Web admin dashboard for managing issuers and clients
- REST API for programmatic test setup and teardown
- OpenID Connect Discovery and JWKS endpoints
- SQLite storage with embedded assets - single binary, zero dependencies
- CORS support for SPA testing
- Health and readiness endpoints for container orchestration

## Quickstart

### From source

```sh
go install github.com/jirwin/oidc-test@latest
oidc-test
```

Or build locally:

```sh
git clone https://github.com/jirwin/oidc-test.git
cd oidc-test
make build
./oidc-test
```

### Docker

```sh
docker compose up
```

Or run directly:

```sh
docker run -p 8080:8080 -v oidc-data:/data ghcr.io/jirwin/oidc-test -db-path /data/oidc-test.db
```

The admin UI is available at http://localhost:8080/admin.

## Configuration

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `-port` | | `8080` | HTTP listen port |
| `-base-url` | `BASE_URL` | `http://localhost:{port}` | External base URL used in issuer claims |
| `-db-path` | | `oidc-test.db` | SQLite database file path |
| `-access-token-ttl` | | `1h` | Access token lifetime |
| `-refresh-token-ttl` | | `720h` | Refresh token lifetime (default 30 days) |
| `-auth-code-ttl` | | `10m` | Authorization code lifetime |
| `-cors-origins` | | `*` | Allowed CORS origins (comma-separated, or `*` for all) |
| `-admin-token` | | | Optional Bearer token to protect the management API |

## OIDC Endpoints

All endpoints are scoped per issuer. Replace `{id}` with the issuer ID.

| Endpoint | Path |
|----------|------|
| Discovery | `GET /issuers/{id}/.well-known/openid-configuration` |
| Authorization | `GET /issuers/{id}/authorize` |
| Token | `POST /issuers/{id}/token` |
| UserInfo | `GET/POST /issuers/{id}/userinfo` |
| JWKS | `GET /issuers/{id}/jwks` |
| Introspection | `POST /issuers/{id}/introspect` |
| Logout | `GET /issuers/{id}/logout` |

## Management API

Programmatic issuer and client management for CI/CD and automated test setup.

```sh
# Create an issuer
curl -X POST http://localhost:8080/api/issuers \
  -H 'Content-Type: application/json' \
  -d '{"name": "test-issuer", "scopes": "openid profile email"}'

# List issuers
curl http://localhost:8080/api/issuers

# Create a client
curl -X POST http://localhost:8080/api/issuers/{id}/clients \
  -H 'Content-Type: application/json' \
  -d '{"name": "my-app", "redirect_uri": "http://localhost:3000/callback"}'

# List clients
curl http://localhost:8080/api/issuers/{id}/clients
```

If `-admin-token` is set, include `Authorization: Bearer <token>` on all management API requests.

## Authentication

The login form accepts any username and password. Usernames starting with "admin" (case-insensitive) automatically receive the `admin` scope. This is intentional - oidc-test is a testing tool, not a production identity provider.

## Custom Claims

Custom claims can be configured at the issuer, client, or user level via the admin UI or management API. Claims are applied in priority order: issuer defaults < client overrides < user overrides. Claim values are JSON-encoded.

```sh
# Set a custom claim at the issuer level
curl -X POST http://localhost:8080/api/issuers/{id}/claims \
  -H 'Content-Type: application/json' \
  -d '{"claim_key": "department", "claim_value": "\"engineering\""}'

# Set a custom claim for a specific user
curl -X POST http://localhost:8080/api/issuers/{id}/claims \
  -H 'Content-Type: application/json' \
  -d '{"claim_key": "role", "claim_value": "\"admin\"", "username": "testuser"}'
```

## TLS / HTTPS

oidc-test serves plain HTTP. For HTTPS with a valid TLS certificate, run it behind a reverse proxy.

### Caddy (recommended)

[Caddy](https://caddyserver.com/) handles Let's Encrypt certificates automatically with no configuration:

```
oidc.example.com {
    reverse_proxy localhost:8080
}
```

Run with `caddy run --config Caddyfile`. Caddy provisions and renews certificates on its own.

### nginx

```nginx
server {
    listen 443 ssl;
    server_name oidc.example.com;

    ssl_certificate /etc/letsencrypt/live/oidc.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/oidc.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Use [certbot](https://certbot.eff.org/) to obtain and renew Let's Encrypt certificates.

When running behind a reverse proxy, set `-base-url` to your external HTTPS URL so that issuer claims and discovery documents contain the correct addresses:

```sh
./oidc-test -port 8080 -base-url https://oidc.example.com
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).
