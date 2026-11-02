---
title: "Server Endpoints & Metadata"
weight: 2
---

# Server Endpoints & Discovery Metadata

`OAuth2AuthorizationServerFilter` exposes standard RFC and OpenID Connect endpoints by implementing `SecurityEndpointRegistration`.

---

## 🌐 Endpoints Summary

| Endpoint | Method | RFC / Spec | Purpose |
| :--- | :--- | :--- | :--- |
| `/oauth2/authorize` | `GET` | RFC 6749 / OAuth 2.1 | Authorization endpoint. Authenticates user and issues authorization code. |
| `/oauth2/token` | `POST` | RFC 6749 | Token exchange endpoint for `authorization_code`, `client_credentials`, and `refresh_token`. |
| `/oauth2/jwks` | `GET` | RFC 7517 | Exposes the JSON Web Key Set containing public signing keys. |
| `/oauth2/introspect` | `POST` | RFC 7662 | Validates active status and metadata of access/refresh tokens. |
| `/oauth2/revoke` | `POST` | RFC 7009 | Invalidates a specific access or refresh token. |
| `/.well-known/openid-configuration` | `GET` | OIDC Core 1.0 | Provides automated discovery metadata for OIDC and OAuth 2.0 clients. |

---

## 🔍 Discovery Metadata Example

Calling `GET /.well-known/openid-configuration` returns:

```json
{
  "issuer": "https://auth.company.com",
  "authorization_endpoint": "https://auth.company.com/oauth2/authorize",
  "token_endpoint": "https://auth.company.com/oauth2/token",
  "jwks_uri": "https://auth.company.com/oauth2/jwks",
  "revocation_endpoint": "https://auth.company.com/oauth2/revoke",
  "introspection_endpoint": "https://auth.company.com/oauth2/introspect",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```
