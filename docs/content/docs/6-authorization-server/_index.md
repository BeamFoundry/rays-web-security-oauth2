---
title: "6. Authorization Server"
weight: 6
bookCollapseSection: false
---

# OAuth 2.1 Authorization Server
 
**Rays OAuth2 Authorization Server** is a full-featured, standards-compliant OAuth 2.0 / OAuth 2.1 authorization server implementation modeled after the **Spring Authorization Server** project. Note that while discovery metadata (`/.well-known/openid-configuration`) is supported for OAuth metadata discovery, the current token response path does not emit OIDC ID tokens; this module currently functions as an OAuth authorization server without OpenID Connect provider support.
 
It provides out-of-the-box endpoints for authorization code generation (with mandatory or optional PKCE), client authentication, token issuance, public key sets (JWKS), token introspection, and token revocation.

---

## 🏛️ Architecture Overview

```
                      ┌──────────────────────────────────────┐
                      │    OAuth2AuthorizationServerFilter   │
                      │   (SecurityEndpointRegistration)     │
                      └──────────────────┬───────────────────┘
                                         │
        ┌──────────────┬─────────────────┼────────────────┬──────────────┐
        ▼              ▼                 ▼                ▼              ▼
  /oauth2/authorize  /oauth2/token     /oauth2/jwks   /introspect    /revoke
        │              │                 │                │              │
        ▼              ▼                 ▼                ▼              ▼
 ┌──────────────┬──────────────────┬──────────────┬──────────────────────┐
 │ Registered   │  Authorization   │  JWKSource   │  Token Generator     │
 │ Client Repo  │  Service (State) │  (RSA/ECDSA) │  (Signed JWTs)       │
 └──────────────┴──────────────────┴──────────────┴──────────────────────┘
```

---

## 📂 Subtopics

1. [Registered Clients & Grants](/rays-web-security-oauth2/docs/6-authorization-server/1-registered-clients/)
2. [Server Endpoints & Metadata](/rays-web-security-oauth2/docs/6-authorization-server/2-endpoints/)
3. [Key Management & Token Issuance](/rays-web-security-oauth2/docs/6-authorization-server/3-token-issuance/)
