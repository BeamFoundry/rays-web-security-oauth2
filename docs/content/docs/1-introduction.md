---
title: "1. Introduction"
weight: 1
---

# Introduction & Architecture

Modern distributed systems require flexible, standardized identity protocols. **Rays OAuth2** (`github.com/BeamFoundry/rays-web-security-oauth2`) is designed from the ground up to bring the mature design patterns of **Spring Security OAuth2** (Spring Security 6.x & Spring Authorization Server) to Go and the Rays ecosystem.

It operates as an extension of [`github.com/BeamFoundry/rays-web-security`](https://rays.bfdy.dev/rays-web-security/), connecting seamlessly into its request lifecycle, security contexts, and IoC container.

---

## 🏛️ Architectural Alignment with `rays-web-security`

Rays Web Security structures web security around declarative **Security Filter Chains**, **Authentication Providers**, and a thread/routine-local **SecurityContext**. Rays OAuth2 connects directly to these core abstractions:

| `rays-web-security` Interface | `rays-web-security-oauth2` Implementation | Description |
| :--- | :--- | :--- |
| `SecurityFilter` | `OAuth2LoginAuthenticationFilter`, `BearerTokenAuthenticationFilter`, `OAuth2AuthorizationServerFilter` | Intercepts HTTP requests, extracts authorization codes or Bearer tokens, and dictates chain continuation or challenges. |
| `SecurityEndpointRegistration` | `OAuth2LoginAuthenticationFilter`, `OAuth2AuthorizationServerFilter` | Automatically binds technical endpoints (`/oauth2/authorization/{id}`, `/login/oauth2/code/{id}`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/jwks`, etc.) to the underlying web router. |
| `Authentication` | `OAuth2AuthenticationToken`, `OAuth2LoginAuthenticationToken`, `BearerTokenAuthenticationToken`, `JwtAuthenticationToken` | Encapsulates unauthenticated requests and authenticated principals, authorities, and credentials. |
| `AuthenticationManager` | *(Already provided by `rays-web-security`)* | Injected into OAuth2 filters. It automatically routes authentication requests to matching providers. |
| `AuthenticationProvider` | `OAuth2LoginAuthenticationProvider`, `JwtAuthenticationProvider` | Specialized providers implementing `Supports(auth)` and `Authenticate(auth)`. Auto-injected into the `AuthenticationManager`. |
| `SecurityContextHolder` | `securityContextHolder.GetContext().SetAuthentication(...)` | Stores the authenticated `Authentication` in routine-local storage, accessible anywhere downstream. |

---

## ⚡ The `AuthenticationManager` & `AuthenticationProvider` Relationship

An essential design principle of Rays Web Security is its pluggable provider architecture:

1. **`AuthenticationManager` is native to `rays-web-security`:**
   `rays-web-security` already provides a central manager (`AuthenticationProviderManager`). It automatically collects **all** beans implementing `AuthenticationProvider` via Rays IoC injection:
   ```go
   type AuthenticationProviderManager struct {
       Service
       Manager
       providers []AuthenticationProvider `@:"Inject"`
   }
   ```
2. **`rays-web-security-oauth2` provides specialized `AuthenticationProvider` beans:**
   Rather than reinventing an authentication manager, `rays-web-security-oauth2` defines domain-specific providers:
   *   `OAuth2LoginAuthenticationProvider`: Authenticates authorization codes and exchanges them for user profiles.
   *   `JwtAuthenticationProvider`: Validates JWT Bearer tokens and extracts granted authorities.
3. **Automatic Provider Routing:**
   When you register one of these providers as a Beam, `rays-web-security`'s `AuthenticationManager` automatically detects it. When a filter calls:
   ```go
   authenticated, err := this.authenticationManager.Authenticate(token)
   ```
   The `AuthenticationManager` iterates through its providers, calls `Supports(token)`, and delegates execution to your OAuth2 provider.
4. **Routine-Local Context Registration:**
   Upon successful authentication, the filter sets the resulting `Authentication` into the `SecurityContextHolder` (and user session, if stateful), making it immediately available to subsequent handlers and downstream service layers.

## 🧩 The Four Functional Pillars

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Rays OAuth2 Modules                           │
├──────────────────┬──────────────────┬──────────────────┬───────────────┤
│   OAuth2 Login   │  OAuth2 Client   │ Resource Server  │ Auth Server   │
│                  │                  │                  │               │
│ • SSO with IdPs  │ • Token Storage  │ • Bearer Tokens  │ • OAuth 2.1   │
│ • Auth Code Flow │ • Refresh Token  │ • JWT Decoder    │ • /authorize  │
│ • PKCE (S256)    │ • Client Creds   │ • Claims to Auth │ • /token      │
│ • OIDC id_token  │ • API Helper     │ • JWKS Rotation  │ • /jwks       │
│ • UserInfo Sync  │ • AuthorizedMgr  │ • Scopes / Roles │ • /introspect │
└──────────────────┴──────────────────┴──────────────────┴───────────────┘
```

1. **OAuth2 Login (`pkg/login`):** Enables user authentication into your web application via external identity providers (Google, GitHub, Keycloak, etc.) with automatic session establishment.
2. **OAuth2 Client (`pkg/client`):** Manages OAuth2 client credentials, access tokens, refresh tokens, and outbound authorized API requests.
3. **OAuth2 Resource Server (`pkg/resourceserver`):** Protects HTTP APIs by validating incoming Bearer JWT tokens against signatures, expiration, issuers, and audiences.
4. **OAuth2 Authorization Server (`pkg/server`):** OAuth 2.1 Authorization Server that authenticates clients, validates authorization codes with PKCE, and issues signed JWTs (without OpenID Connect ID token issuance).

---

## 📦 Package Structure & Imports

*   `github.com/BeamFoundry/rays-web-security-oauth2`: Root module entry point.
*   `.../pkg/core`: Core domain models (`ClientRegistration`, `OAuth2AccessToken`, `OAuth2User`, `OAuth2Error`, `OAuth2AuthenticationToken`).
*   `.../pkg/jwt`: Cryptographic JWT signing (RSA/HMAC), verification, validation, and JSON Web Key Sets (`JWK`, `JWKSet`, `JWKSource`).
*   `.../pkg/client`: Client repository, authorized client service, and authorized client manager.
*   `.../pkg/login`: OAuth2 login filter, authorization code exchange, and UserInfo/OIDC services.
*   `.../pkg/resourceserver`: Bearer token filter, token resolver, and JWT authentication provider.
*   `.../pkg/server`: Authorization Server filter, endpoints (`/token`, `/authorize`, `/jwks`, `/introspect`, `/revoke`), and token generators.
*   `.../pkg/config`: Fluent configurers for `HttpSecurityBuilder`.

---

## 🧹 Simplifying with Imports

To write clean, expressive security configurations, follow the Rays Framework convention and dot-import all BeamFoundry packages:

```go
import (
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
)
```
