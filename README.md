# BeamFoundry Rays Web Security OAuth2 🔐

[![Go Version](https://img.shields.io/badge/Go-1.27+-00ADD8?style=flat&logo=go)](https://golang.org)
[![codecov](https://codecov.io/gh/BeamFoundry/rays-web-security-oauth2/graph/badge.svg)](https://codecov.io/gh/BeamFoundry/rays-web-security-oauth2)

**This is an extract of the full documentation available at [rays.bfdy.dev](https://rays.bfdy.dev/rays-web-security-oauth2/).**

**Rays Web Security OAuth2** brings the comprehensive, enterprise-grade architecture of **Spring Security OAuth2** (Spring Security 6.x & Spring Authorization Server) directly to Go and the Rays framework.

Designed as the dedicated OAuth 2.0 and OpenID Connect 1.0 extension for [`github.com/BeamFoundry/rays-web-security`](https://rays.bfdy.dev/rays-web-security/), it plugs directly into standard security interfaces (`SecurityFilter`, `SecurityEndpointRegistration`, `AuthenticationManager`, `AuthenticationProvider`, and `SecurityContextHolder`).

It delivers four complete, production-ready modules:

1. **OAuth2 Login:** Federated authentication (SSO) with OpenID Connect (OIDC) & OAuth2 providers (Google, GitHub, Keycloak, Okta) using the Authorization Code grant with PKCE.
2. **OAuth2 Client:** Managing client registrations, handling token refresh, client credentials machine-to-machine calls, and accessing protected external APIs.
3. **OAuth2 Resource Server:** Protecting HTTP APIs using Bearer tokens (RFC 6750) with cryptographic JWT verification (JWK sets, key rotation, claims validation).
4. **OAuth2 Authorization Server:** OAuth 2.1 Authorization Server that authenticates clients, validates authorization codes with PKCE, and issues signed JWT access tokens, refresh tokens, and JWK sets.

---

## Table of Contents

- [Introduction & Architecture](#introduction--architecture)
  - [Architectural Alignment with rays-web-security](#architectural-alignment-with-rays-web-security)
  - [The AuthenticationManager & AuthenticationProvider Relationship](#the-authenticationmanager--authenticationprovider-relationship)
  - [The Four Functional Pillars](#the-four-functional-pillars)
  - [Package Structure & Imports](#package-structure--imports)
- [Quickstart & Setup](#quickstart--setup)
  - [Installation](#installation)
  - [Quickstart 1: Protecting an API (Resource Server)](#quickstart-1-protecting-an-api-resource-server)
  - [Quickstart 2: Social Login / SSO (OAuth2 Login)](#quickstart-2-social-login--sso-oauth2-login)
  - [The Application Entrypoint](#the-application-entrypoint)
- [OAuth2 Login (SSO & OpenID Connect)](#oauth2-login-sso--openid-connect)
  - [The Authentication Flow](#the-authentication-flow)
  - [Defining Client Registrations](#defining-client-registrations)
  - [User Services & Claims Mapping](#user-services--claims-mapping)
  - [Login Filter & Technical Endpoints](#login-filter--technical-endpoints)
- [OAuth2 Client (API Consumption)](#oauth2-client-api-consumption)
  - [Core Model: OAuth2AuthorizedClient](#core-model-oauth2authorizedclient)
  - [Client Manager & Providers](#client-manager--providers)
  - [Calling Remote APIs](#calling-remote-apis)
- [OAuth2 Resource Server](#oauth2-resource-server)
  - [The Request Lifecycle](#the-request-lifecycle)
  - [JWT Validation & JWK Sets](#jwt-validation--jwk-sets)
  - [Claims & Authority Conversion](#claims--authority-conversion)
  - [Opaque Tokens & Introspection](#opaque-tokens--introspection)
- [OAuth 2.1 Authorization Server](#oauth-21-authorization-server)
  - [Architecture Overview](#architecture-overview)
  - [Registering Clients & Grants](#registering-clients--grants)
  - [Server Endpoints & Metadata](#server-endpoints--metadata)
  - [Key Management & Token Issuance](#key-management--token-issuance)
- [Fluent Configuration DSL (Go 1.27+)](#fluent-configuration-dsl-go-127)
  - [Generic With() Configuration](#generic-with-configuration)
  - [Prototype SecurityFilter Lifecycle](#prototype-securityfilter-lifecycle)
  - [Complete DSL Examples](#complete-dsl-examples)
- [Testing & Security Assurance](#testing--security-assurance)
  - [Ginkgo Test Suite Setup](#ginkgo-test-suite-setup)
  - [Testing Resource Server with Mock JWTs](#testing-resource-server-with-mock-jwts)
  - [Testing Filters with MockSecurityHandler](#testing-filters-with-mocksecurityhandler)
  - [In-Memory Repositories](#in-memory-repositories)
  - [Security Attack Testing & Race Prevention](#security-attack-testing--race-prevention)
  - [Running the Test Suites](#running-the-test-suites)

---

## Introduction & Architecture

Modern distributed systems require flexible, standardized identity protocols. **Rays Web Security OAuth2** (`github.com/BeamFoundry/rays-web-security-oauth2`) is designed from the ground up to bring the mature design patterns of **Spring Security OAuth2** (Spring Security 6.x & Spring Authorization Server) to Go and the Rays ecosystem.

It operates as an extension of [`github.com/BeamFoundry/rays-web-security`](https://rays.bfdy.dev/rays-web-security/), connecting seamlessly into its request lifecycle, security contexts, and IoC container.

### Architectural Alignment with `rays-web-security`

Rays Web Security structures web security around declarative **Security Filter Chains**, **Authentication Providers**, and a routine-local **SecurityContext**. Rays Web Security OAuth2 connects directly to these core abstractions:

| `rays-web-security` Interface | `rays-web-security-oauth2` Implementation | Description |
| :--- | :--- | :--- |
| `SecurityFilter` | `OAuth2LoginAuthenticationFilter`, `BearerTokenAuthenticationFilter`, `OAuth2AuthorizationServerFilter` | Intercepts HTTP requests, extracts authorization codes or Bearer tokens, and dictates chain continuation or challenges. |
| `SecurityEndpointRegistration` | `OAuth2LoginAuthenticationFilter`, `OAuth2AuthorizationServerFilter` | Automatically binds technical endpoints (`/oauth2/authorization/{id}`, `/login/oauth2/code/{id}`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/jwks`, etc.) to the underlying web router. |
| `Authentication` | `OAuth2AuthenticationToken`, `OAuth2LoginAuthenticationToken`, `BearerTokenAuthenticationToken`, `JwtAuthenticationToken` | Encapsulates unauthenticated requests and authenticated principals, authorities, and credentials. |
| `AuthenticationManager` | *(Provided by `rays-web-security`)* | Injected into OAuth2 filters. It automatically routes authentication requests to matching providers. |
| `AuthenticationProvider` | `OAuth2LoginAuthenticationProvider`, `JwtAuthenticationProvider` | Specialized providers implementing `Supports(auth)` and `Authenticate(auth)`. Auto-injected into `AuthenticationManager`. |
| `SecurityContextHolder` | `securityContextHolder.GetContext().SetAuthentication(...)` | Stores the authenticated `Authentication` in routine-local storage, accessible anywhere downstream. |

### The `AuthenticationManager` & `AuthenticationProvider` Relationship

An essential design principle of Rays Web Security is its pluggable provider architecture:

1. **`AuthenticationManager` is native to `rays-web-security`:**
   `rays-web-security` provides `AuthenticationProviderManager`, which automatically collects **all** beans implementing `AuthenticationProvider` via Rays IoC injection:
   ```go
   type AuthenticationProviderManager struct {
       Service
       Manager
       providers []AuthenticationProvider `@:"Inject"`
   }
   ```
2. **`rays-web-security-oauth2` provides specialized `AuthenticationProvider` beans:**
   Rather than reinventing an authentication manager, `rays-web-security-oauth2` defines domain-specific providers:
   - `OAuth2LoginAuthenticationProvider`: Authenticates authorization codes and exchanges them for user profiles.
   - `JwtAuthenticationProvider`: Validates JWT Bearer tokens and extracts granted authorities.
3. **Automatic Provider Routing:**
   When you register one of these providers as a Beam, `rays-web-security`'s `AuthenticationManager` automatically detects it. When a filter calls `this.authenticationManager.Authenticate(token)`, the manager iterates through its providers, calls `Supports(token)`, and delegates execution to your OAuth2 provider.
4. **Routine-Local Context Registration:**
   Upon successful authentication, the filter sets the resulting `Authentication` into the `SecurityContextHolder` (and user session, if stateful), making it immediately available to subsequent handlers and downstream service layers.

### The Four Functional Pillars

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Rays Web Security OAuth2 Modules                     │
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
4. **OAuth2 Authorization Server (`pkg/server`):** OAuth 2.1 Authorization Server that authenticates clients, validates authorization codes with PKCE, and issues signed JWTs.

### Package Structure & Imports

- `github.com/BeamFoundry/rays-web-security-oauth2`: Root module entry point.
- `.../pkg/core`: Core domain models (`ClientRegistration`, `OAuth2AccessToken`, `OAuth2User`, `OAuth2Error`, `OAuth2AuthenticationToken`).
- `.../pkg/jwt`: Cryptographic JWT signing (RSA/HMAC), verification, validation, and JSON Web Key Sets (`JWK`, `JWKSet`, `JWKSource`).
- `.../pkg/client`: Client repository, authorized client service, and authorized client manager.
- `.../pkg/login`: OAuth2 login filter, authorization code exchange, and UserInfo/OIDC services.
- `.../pkg/resourceserver`: Bearer token filter, token resolver, and JWT authentication provider.
- `.../pkg/server`: Authorization Server filter, endpoints (`/token`, `/authorize`, `/jwks`, `/introspect`, `/revoke`), and token generators.
- `.../pkg/config`: Fluent configurers for `HttpSecurityBuilder`.

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

---

## Quickstart & Setup

### Installation

Add both `rays-web-security` and `rays-web-security-oauth2` to your Go module:

```bash
go get github.com/BeamFoundry/rays-web-security
go get github.com/BeamFoundry/rays-web-security-oauth2
```

### Quickstart 1: Protecting an API (Resource Server)

If you are building a REST API that accepts incoming Bearer JWT tokens issued by an identity provider (e.g. Keycloak, Auth0, or your own Authorization Server):

```go
package configurations

import (
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/resourceserver"
)

type ResourceServerSecurityConfig struct {
    Configuration
}

// 1. Register a JwtDecoder bean configured with the expected issuer and audience.
func (this *ResourceServerSecurityConfig) JwtDecoder() JwtDecoder {
    return NewJwxJwtDecoderWithRemoteJWKS("https://auth.example.com/.well-known/jwks.json").
        WithIssuer("https://auth.example.com").
        WithAudience("my-api")
}

// 2. Register the JwtAuthenticationProvider as a Beam.
// rays-web-security's AuthenticationManager automatically injects all AuthenticationProvider beans!
func (this *ResourceServerSecurityConfig) JwtAuthenticationProvider(
    that struct {
        decoder JwtDecoder `@:"Inject"`
    },
) AuthenticationProvider {
    return JwtAuthenticationProvider{}.New(that.decoder)
}

// 3. Configure HttpSecurity
func (this *ResourceServerSecurityConfig) HttpSecurity() *HttpSecurity {
    // Registers BearerTokenAuthenticationFilter fluently via With().
    // Rays auto-injects AuthenticationManager and SecurityContextHolder into the filter prototype.
    return (&HttpSecurityBuilder{}).
        With(OAuth2ResourceServer).
            Realm("my-api").
        And().
        Csrf().Disable().
        SessionCreationPolicy().Stateless().
        AuthorizedHTTPRequests().
            Paths("/api/public/**").PermitAll().
            Paths("/api/admin/**").HasAuthority("SCOPE_admin").
            AnyRequest().Authenticated().
        And().
        Build()
}
```

### Quickstart 2: Social Login / SSO (OAuth2 Login)

If you are building a web application where users sign in using an external provider like GitHub:

```go
package configurations

import (
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/config"
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/login"
)

type WebSecurityConfig struct {
    Configuration
}

// 1. Register client definitions
func (this *WebSecurityConfig) ClientRepository() ClientRegistrationRepository {
    githubClient := ClientRegistrationBuilder{}.New("github").
        ClientID("your-github-client-id").
        ClientSecret("your-github-client-secret").
        AuthorizationURI("https://github.com/login/oauth/authorize").
        TokenURI("https://github.com/login/oauth/access_token").
        RedirectURI("https://app.example.com/login/oauth2/code/github").
        UserInfoURI("https://api.github.com/user").
        UserNameAttributeName("login").
        Scope("read:user", "user:email").
        Build()

    return InMemoryClientRegistrationRepository{}.New(githubClient)
}

// 2. Register OAuth2LoginAuthenticationProvider as a Beam.
// rays-web-security's AuthenticationManager automatically injects it!
func (this *WebSecurityConfig) OAuth2LoginAuthenticationProvider() AuthenticationProvider {
    return OAuth2LoginAuthenticationProvider{}.New(nil, nil, nil)
}

// 3. Configure HttpSecurity
func (this *WebSecurityConfig) HttpSecurity(
    that struct {
        clientRepo ClientRegistrationRepository `@:"Inject"`
    },
) *HttpSecurity {
    // Registers OAuth2LoginAuthenticationFilter fluently via With().
    // AuthenticationManager and SecurityContextHolder are auto-injected by Rays.
    return (&HttpSecurityBuilder{}).
        With(OAuth2Login).
            ClientRegistrationRepository(that.clientRepo).
            DefaultRegistrationID("github").
            BaseURL("https://app.example.com").
            DefaultSuccessURL("/dashboard").
        And().
        AuthorizedHTTPRequests().
            Paths("/", "/login/**", "/static/**").PermitAll().
            AnyRequest().Authenticated().
        And().
        Build()
}
```

### The Application Entrypoint

In your `main.go`, bootstrap the Rays container. Both `rays-web-security` and `rays-web-security-oauth2` components will be discovered and registered:

```go
package main

import (
    "os"
    . "github.com/BeamFoundry/rays"
    _ "github.com/BeamFoundry/rays-web-security"
    _ "github.com/BeamFoundry/rays-web-security-oauth2"
)

func main() {
    ctx := ApplicationContext()
    ctx.EnableScanning()

    if err := ctx.Initialize(); err != nil {
        err.LogErrorWithStackTrace()
        os.Exit(1)
    }

    ctx.Run()
}
```

---

## OAuth2 Login (SSO & OpenID Connect)

**OAuth2 Login** provides web applications with the ability to have users log in using their existing accounts at an external OAuth 2.0 or OpenID Connect 1.0 provider (such as Google, GitHub, Keycloak, or Okta).

Modeled after Spring Security's `oauth2Login()`, this feature automates the entire Authorization Code grant lifecycle, including **Proof Key for Code Exchange (PKCE)** and state parameter validation.

### The Authentication Flow

```
1. Unauthenticated request to protected route
   └─► Redirects to /oauth2/authorization/{registrationId}

2. Authorization Request Initiation
   └─► Generates cryptographically secure State, Nonce, and PKCE (code_verifier & code_challenge S256)
   └─► Saves OAuth2AuthorizationRequest into HTTP session
   └─► 302 Redirect to Provider's Authorization Endpoint

3. User signs in & consents at Identity Provider
   └─► Provider redirects back to /login/oauth2/code/{registrationId}?code=xyz&state=abc

4. Callback Processing & Token Exchange
   └─► OAuth2LoginAuthenticationFilter validates state matches session
   └─► AuthenticationManager delegates to OAuth2LoginAuthenticationProvider
   └─► POST {tokenUri} exchanging code + code_verifier for access_token and id_token
   └─► Decodes OIDC id_token or calls {userInfoUri}
   └─► Instantiates OAuth2User / OidcUser with GrantedAuthorities
   └─► Saves OAuth2AuthenticationToken into SecurityContextHolder & session
   └─► 302 Redirect to user's originally requested URL
```

### Defining Client Registrations

A `ClientRegistration` represents the configuration required to communicate with an external provider:

```go
package configurations

import (
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
)

type OAuth2ClientsConfig struct {
    Configuration
}

func (this *OAuth2ClientsConfig) ClientRegistrationRepository() ClientRegistrationRepository {
    // 1. Google OpenID Connect Registration
    google := ClientRegistrationBuilder{}.New("google").
        ClientID("your-google-client-id.apps.googleusercontent.com").
        ClientSecret("your-google-client-secret").
        ClientAuthenticationMethod(ClientAuthMethodBasic).
        AuthorizationGrantType(GrantTypeAuthorizationCode).
        RedirectURI("/login/oauth2/code/google").
        Scope("openid", "profile", "email").
        AuthorizationURI("https://accounts.google.com/o/oauth2/v2/auth").
        TokenURI("https://oauth2.googleapis.com/token").
        UserInfoURI("https://openidconnect.googleapis.com/v1/userinfo").
        JwkSetURI("https://www.googleapis.com/oauth2/v3/certs").
        UserNameAttributeName("sub").
        ClientName("Google").
        Build()

    // 2. GitHub OAuth2 Registration
    github := ClientRegistrationBuilder{}.New("github").
        ClientID("github-client-id").
        ClientSecret("github-client-secret").
        ClientAuthenticationMethod(ClientAuthMethodPost).
        AuthorizationGrantType(GrantTypeAuthorizationCode).
        RedirectURI("/login/oauth2/code/github").
        Scope("read:user", "user:email").
        AuthorizationURI("https://github.com/login/oauth/authorize").
        TokenURI("https://github.com/login/oauth/access_token").
        UserInfoURI("https://api.github.com/user").
        UserNameAttributeName("login").
        ClientName("GitHub").
        Build()

    return InMemoryClientRegistrationRepository{}.New(google, github)
}
```

### User Services & Claims Mapping

When authentication completes successfully, an implementation of `OAuth2User` (or `OidcUser` for OpenID Connect) is stored inside the `Authentication.GetPrincipal()` object:

```go
type OAuth2User interface {
    GetName() string
    GetAttributes() map[string]any
    GetAuthorities() []GrantedAuthority
}

type OidcUser interface {
    OAuth2User
    GetIdToken() *OidcIdToken
    GetUserInfo() *OidcUserInfo
}
```

- **`DefaultOAuth2UserService`**: Queries the provider's `UserInfoURI` with `Authorization: Bearer <token>`, parses the JSON payload, and maps scopes to authorities (`SCOPE_<name>`).
- **`DefaultOidcUserService`**: Decodes and verifies the `id_token` claims (subject, email, profile) and merges them with optional UserInfo endpoint claims.

#### Customizing User Mapping

You can supply your own `OAuth2UserService` to assign application-specific roles:

```go
type CustomOAuth2UserService struct {
    defaultService *DefaultOAuth2UserService
}

func (this *CustomOAuth2UserService) LoadUser(req *OAuth2UserRequest) (OAuth2User, Error) {
    user, err := this.defaultService.LoadUser(req)
    if err != nil {
        return nil, err
    }

    authorities := user.GetAuthorities()
    
    // Check if user is an admin in our database
    if email, ok := user.GetAttributes()["email"].(string); ok && email == "admin@example.com" {
        authorities = append(authorities, Authority("ROLE_ADMIN"))
    } else {
        authorities = append(authorities, Authority("ROLE_USER"))
    }

    return NewDefaultOAuth2User(authorities, user.GetAttributes(), "name"), nil
}
```

### Login Filter & Technical Endpoints

`OAuth2LoginAuthenticationFilter` automatically registers technical endpoints on the web router:

1. **Authorization Redirection:** `GET /oauth2/authorization/{registrationId}`
   - Resolves the matching `ClientRegistration`.
   - Generates a random `state` and PKCE `code_verifier` (with SHA-256 `code_challenge`).
   - Persists the pending `OAuth2AuthorizationRequest` in the user's HTTP session.
   - Redirects the browser to the remote Identity Provider.
2. **Authorization Callback Processing:** `GET /login/oauth2/code/{registrationId}`
   - Extracts `code` and `state` parameters from the query string.
   - Verifies the state matches the stored session to prevent CSRF attacks.
   - Constructs an unauthenticated `OAuth2LoginAuthenticationToken`.
   - Delegates to `AuthenticationManager.Authenticate()`.
   - Stores the authenticated `OAuth2AuthenticationToken` in session and `SecurityContextHolder`.
   - Redirects the user back to their originally requested URL.

---

## OAuth2 Client (API Consumption)

The **OAuth2 Client** module allows your application to act as an OAuth 2.0 client to consume remote protected resources on behalf of an end-user or as the application itself (machine-to-machine).

### Core Model: `OAuth2AuthorizedClient`

An `OAuth2AuthorizedClient` represents an authorized relationship:

```go
type OAuth2AuthorizedClient struct {
    ClientRegistration *ClientRegistration `json:"client_registration"`
    PrincipalName      string              `json:"principal_name"`
    AccessToken        *OAuth2AccessToken  `json:"access_token"`
    RefreshToken       *OAuth2RefreshToken `json:"refresh_token,omitempty"`
}
```

### Client Manager & Providers

The `OAuth2AuthorizedClientManager` coordinates client authorization:

```go
package services

import (
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/lang"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
)

type ApiConsumerService struct {
    clientManager OAuth2AuthorizedClientManager `@:"Inject"`
    clientRepo    ClientRegistrationRepository `@:"Inject"`
}

func (this *ApiConsumerService) GetServiceAccessToken() (string, Error) {
    reg, err := this.clientRepo.FindByRegistrationID("billing-service")
    if err != nil {
        return "", err
    }

    req := &OAuth2AuthorizeRequest{
        ClientRegistration: reg,
        PrincipalName:      "internal-worker",
    }

    // Automatically calls token endpoint with client_credentials
    authorizedClient, err := this.clientManager.Authorize(req)
    if err != nil {
        return "", err
    }

    return authorizedClient.AccessToken.TokenValue, nil
}
```

#### Supported Grant Providers

1. **`ClientCredentialsAuthorizedClientProvider`:** Sends a POST request to the provider's token endpoint with `grant_type=client_credentials`.
2. **`RefreshTokenAuthorizedClientProvider`:** Inspects the current access token's expiration timestamp. If the token is expired (or within a 60-second clock skew threshold) and a refresh token is present, it automatically requests a new access token and updates the persistence store.

### Calling Remote APIs

Once authorized, your application can consume remote APIs with automatic Bearer token injection:

```go
func (this *RemoteApiClient) CallApi(req *http.Request, reg *ClientRegistration, principal string) (*http.Response, Error) {
    authReq := &OAuth2AuthorizeRequest{
        ClientRegistration: reg,
        PrincipalName:      principal,
    }

    authorizedClient, err := this.clientManager.Authorize(authReq)
    if err != nil {
        return nil, err
    }

    if req.URL == nil || req.URL.Scheme != "https" {
        return nil, NewError("InsecureRequestError", "bearer tokens must only be sent over HTTPS")
    }

    req.Header.Set("Authorization", "Bearer "+authorizedClient.AccessToken.TokenValue)
    resp, reqErr := this.httpClient.Do(req)
    if reqErr != nil {
        return nil, NewErrorFrom(reqErr)
    }
    return resp, nil
}
```

---

## OAuth2 Resource Server

An **OAuth2 Resource Server** protects HTTP endpoints by validating incoming OAuth 2.0 Bearer tokens (RFC 6750) included in request headers.

### The Request Lifecycle

```
1. Client requests protected API:
   GET /api/orders
   Authorization: Bearer eyJhbGciOiJSUzI1Ni...

2. BearerTokenAuthenticationFilter resolves token from Authorization header.

3. Creates unauthenticated BearerTokenAuthenticationToken.

4. AuthenticationManager delegates to JwtAuthenticationProvider.

5. JwtDecoder verifies signature using JWK Set (public keys) and checks:
   - exp (expiration with configurable clock skew)
   - nbf (not before)
   - iss (matches expected issuer)
   - aud (matches expected audience)

6. JwtAuthenticationConverter maps scopes to GrantedAuthorities:
   - "read write" -> [SCOPE_read, SCOPE_write]

7. Authenticated JwtAuthenticationToken placed into SecurityContextHolder.

8. Downstream endpoint executes with principal identity.
```

### JWT Validation & JWK Sets

For production environments, `rays-web-security-oauth2` integrates with **`github.com/lestrrat-go/jwx/v3`** (the Go equivalent of Java's Nimbus JOSE+JWT used by Spring Security).

This provides full RFC 7515/7517/7518/7519 compliance and supports **all** signature algorithms:
- **RSA:** `RS256`, `RS384`, `RS512`
- **RSA-PSS:** `PS256`, `PS384`, `PS512`
- **ECDSA:** `ES256`, `ES384`, `ES512` (P-256, P-384, P-521)
- **EdDSA:** `Ed25519`
- **HMAC:** `HS256`, `HS384`, `HS512`

#### Remote JWKS Endpoint (with Key Rotation)

```go
func (this *DecoderConfig) JwtDecoder() JwtDecoder {
    return JwxJwtDecoder{}.NewWithRemoteJWKS("https://auth.company.com/oauth2/jwks").
        WithIssuer("https://auth.company.com").
        WithAudience("my-api-audience").
        WithClockSkew(60 * time.Second)
}

func (this *DecoderConfig) JwtAuthenticationProvider(
    that struct {
        decoder JwtDecoder `@:"Inject"`
    },
) AuthenticationProvider {
    return JwtAuthenticationProvider{}.New(that.decoder)
}
```

#### Validations Performed

1. **Cryptographic Signature:** Verifies RSA (RS256) or HMAC (HS256) using public keys matching the token's `kid` header.
2. **Expiration (`exp`):** Rejects tokens whose expiration timestamp plus clock skew is in the past.
3. **Not Before (`nbf`):** Rejects tokens that are not yet valid.
4. **Issuer (`iss`):** Ensures the issuing authority matches the expected URL.
5. **Audience (`aud`):** Ensures the token was intended for this specific resource server.

### Claims & Authority Conversion

The default converter searches standard claim attributes (`scope`, `scp`, `authorities`, `roles`) and prefixes them with `SCOPE_`:

```go
converter := DefaultJwtAuthenticationConverter{}.New().
    WithPrincipalClaimName("preferred_username").
    WithAuthorityPrefix("ROLE_")

provider := JwtAuthenticationProvider{}.New(decoder).
    WithConverter(converter)
```

Now, endpoint policies can enforce:

```go
AuthorizedHTTPRequests().
    Paths("/api/orders/**").HasAuthority("SCOPE_read").
    Paths("/api/admin/**").HasRole("ADMIN"). // Expects "ROLE_ADMIN"
    AnyRequest().Authenticated()
```

### Opaque Tokens & Introspection

> [!NOTE]
> Resource-server support for opaque tokens via `OpaqueTokenAuthenticationProvider` is currently unavailable. Opaque token introspection flow on the Resource Server side is planned for a future release; currently, Resource Server token validation is supported via stateless JWT verification (`JwtAuthenticationProvider` with `JwtDecoder`).
>
> The Authorization Server provides an RFC 7662 introspection endpoint at `/oauth2/introspect` for clients to query token status. Resource Server integration using an introspection provider will be documented once the provider and its registration exist.

---

## OAuth 2.1 Authorization Server

**Rays Web Security OAuth2 Authorization Server** is a full-featured, standards-compliant OAuth 2.0 / OAuth 2.1 authorization server implementation modeled after the **Spring Authorization Server** project. Note that while discovery metadata (`/.well-known/openid-configuration`) is supported for OAuth metadata discovery, the current token response path does not emit OIDC ID tokens; this module currently functions as an OAuth authorization server without OpenID Connect provider support.

### Architecture Overview

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

### Registering Clients & Grants

A `RegisteredClient` defines the permissions, credentials, and constraints of a client application:

```go
package configurations

import (
    "time"

    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/server"
)

type ClientsConfig struct {
    Configuration
}

func (this *ClientsConfig) RegisteredClientRepository() RegisteredClientRepository {
    // 1. Single-Page App (SPA) with PKCE
    spaClient := &RegisteredClient{
        ID:                          "spa-client-1",
        ClientID:                    "my-react-app",
        ClientName:                  "My React App",
        ClientAuthenticationMethods: []ClientAuthenticationMethod{ClientAuthMethodNone},
        AuthorizationGrantTypes:     []AuthorizationGrantType{GrantTypeAuthorizationCode},
        RedirectURIs:                []string{"http://localhost:3000/callback"},
        Scopes:                      []string{"openid", "profile", "orders:read"},
        RequireProofKey:             true, // Enforces PKCE (S256)
        AccessTokenTimeToLive:       30 * time.Minute,
    }

    // 2. Machine-to-Machine Backend Service
    m2mClient := &RegisteredClient{
        ID:                          "m2m-client-2",
        ClientID:                    "billing-worker",
        ClientSecret:                "worker-super-secret",
        ClientName:                  "Billing Worker",
        ClientAuthenticationMethods: []ClientAuthenticationMethod{ClientAuthMethodBasic},
        AuthorizationGrantTypes:     []AuthorizationGrantType{GrantTypeClientCredentials},
        Scopes:                      []string{"billing:write", "invoices:read"},
        AccessTokenTimeToLive:       1 * time.Hour,
    }

    return InMemoryRegisteredClientRepository{}.New(spaClient, m2mClient)
}
```

### Server Endpoints & Metadata

`OAuth2AuthorizationServerFilter` exposes standard RFC and OpenID Connect endpoints by implementing `SecurityEndpointRegistration`:

| Endpoint | Method | RFC / Spec | Purpose |
| :--- | :--- | :--- | :--- |
| `/oauth2/authorize` | `GET` | RFC 6749 / OAuth 2.1 | Authorization endpoint. Authenticates user and issues authorization code. |
| `/oauth2/token` | `POST` | RFC 6749 | Token exchange endpoint for `authorization_code`, `client_credentials`, and `refresh_token`. |
| `/oauth2/jwks` | `GET` | RFC 7517 | Exposes the JSON Web Key Set containing public signing keys. |
| `/oauth2/introspect` | `POST` | RFC 7662 | Validates active status and metadata of access/refresh tokens. |
| `/oauth2/revoke` | `POST` | RFC 7009 | Invalidates a specific access or refresh token. |
| `/.well-known/openid-configuration` | `GET` | OIDC Core 1.0 | Provides automated discovery metadata for OIDC and OAuth 2.0 clients. |

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

### Key Management & Token Issuance

`RSAKeyManager` generates and manages RSA key pairs:

```go
func (this *KeyConfig) JWKSource() JWKSource {
    km, err := RSAKeyManager{}.New(2048, "auth-key-primary")
    if err != nil {
        panic(err)
    }
    return km
}
```

Using `JwxJwtEncoder`, you can also sign access tokens with ECDSA, Ed25519, or RSA-PSS:

```go
// 1. ECDSA P-256 (ES256)
encoder := JwxJwtEncoder{}.New(ecdsaPrivateKey, jwa.ES256(), "key-es256")

// 2. Ed25519 (EdDSA)
encoder := JwxJwtEncoder{}.New(ed25519PrivateKey, jwa.EdDSA(), "key-eddsa")

// 3. RSA-PSS (PS256)
encoder := JwxJwtEncoder{}.New(rsaPrivateKey, jwa.PS256(), "key-ps256")
```

> [!IMPORTANT]
> The `/oauth2/jwks` endpoint serves the public keys from the separately configured `JWKSource` Beam, **not** directly from `JwxJwtEncoder`. When configuring a custom token encoder (such as the ES256, EdDSA, or PS256 examples above), ensure that your registered `JWKSource` and the encoder share the exact same underlying key material and key identifier (`kid`) so that client applications and Resource Servers can successfully verify token signatures.

---

## Fluent Configuration DSL (Go 1.27+)

### Generic `With()` Configuration

With Go 1.27 generic method support and `rays-web-security` v0.2.0+, `HttpSecurityBuilder` provides:

```go
func (this *HttpSecurityBuilder) With[T HttpSecurityBuilderOption](fn func(*HttpSecurityBuilder) T) T
```

where `HttpSecurityBuilderOption` is:

```go
type HttpSecurityBuilderOption interface {
    And() *HttpSecurityBuilder
}
```

Configurer entrypoint functions (`OAuth2Login`, `OAuth2ResourceServer`, `OAuth2AuthorizationServer`) satisfy `func(*HttpSecurityBuilder) T`.

You no longer need to pre-initialize a local `builder := &HttpSecurityBuilder{}` and manually pass it into configurers. Instead, you can chain directly into `(&HttpSecurityBuilder{}).With(OAuth2Login)`, configure your options fluently, and call `.And()` to return back to the `HttpSecurityBuilder`!

### Prototype SecurityFilter Lifecycle

Custom security filters (`OAuth2LoginAuthenticationFilter`, `BearerTokenAuthenticationFilter`, `OAuth2AuthorizationServerFilter`) are Prototype Beams implementing Rays' `BeamPostConstructWithContext` interface.

When you invoke `.With(OAuth2Login)...And()`, `.With(OAuth2ResourceServer)...And()`, or `.With(OAuth2AuthorizationServer)...And()`, the configurer registers the filter's configuration into `HttpSecurity` via `AddCustomSecurityFilter(name, cfg)`.

When the Rays IoC container builds and initializes `HttpSecurity`, it matches the configured filter names, dynamically instantiates the prototype filters, injects their container dependencies (such as `AuthenticationManager`, `SecurityContextHolder`, and registered repositories) directly, and runs `WithContext(ctx)`. This eliminates the need to manually inject and forward `AuthenticationManager` or `SecurityContextHolder` in your `HttpSecurity(...)` configuration method!

### Complete DSL Examples

#### 1. OAuth2 Login Configuration

```go
package config

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays/pkg/core"
)

type SecurityConfig struct {
	Configuration
}

func (this *SecurityConfig) HttpSecurity(
	that struct {
		clientRepo ClientRegistrationRepository `@:"Inject"`
	},
) *HttpSecurity {
	// AuthenticationManager and SecurityContextHolder are auto-injected by Rays
	return (&HttpSecurityBuilder{}).
		With(OAuth2Login).
			ClientRegistrationRepository(that.clientRepo).
			DefaultRegistrationID("github").
			DefaultSuccessURL("/dashboard").
		And().
		AuthorizedHTTPRequests().
			Paths("/", "/login/**").PermitAll().
			AnyRequest().Authenticated().
		And().
		Build()
}
```

#### 2. Resource Server (JWT) Configuration

```go
package config

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays/pkg/core"
)

type ResourceServerSecurityConfig struct {
	Configuration
}

func (this *ResourceServerSecurityConfig) HttpSecurity() *HttpSecurity {
	// AuthenticationManager and SecurityContextHolder are auto-injected by Rays
	return (&HttpSecurityBuilder{}).
		With(OAuth2ResourceServer).
			Realm("orders-api").
		And().
		Csrf().Disable().
		SessionCreationPolicy().Stateless().
		AuthorizedHTTPRequests().
			Paths("/api/public/**").PermitAll().
			Paths("/api/orders/**").HasAuthority("SCOPE_orders:read").
			AnyRequest().Authenticated().
		And().
		Build()
}
```

#### 3. Authorization Server Configuration

```go
package config

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/server"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays/pkg/core"
)

type AuthServerSecurityConfig struct {
	Configuration
}

func (this *AuthServerSecurityConfig) HttpSecurity(
	that struct {
		clientRepo  RegisteredClientRepository  `@:"Inject"`
		authService OAuth2AuthorizationService `@:"Inject"`
		jwkSource   JWKSource                   `@:"Inject"`
	},
) *HttpSecurity {
	// SecurityContextHolder is auto-injected by Rays into the prototype filter
	return (&HttpSecurityBuilder{}).
		With(OAuth2AuthorizationServer).
			Settings(AuthorizationServerSettings{}.NewDefault("https://auth.company.com")).
			RegisteredClientRepository(that.clientRepo).
			AuthorizationService(that.authService).
			JWKSource(that.jwkSource).
		And().
		FormLogin().And(). // Authenticates users for /oauth2/authorize
		Build()
}
```

---

## Testing & Security Assurance

All `rays-web-security-oauth2` components are tested using the [Ginkgo v2](https://onsi.github.io/ginkgo/) BDD testing framework and [Gomega](https://onsi.github.io/gomega/) matcher library, following the standardized testing conventions of the **Rays Framework** and `rays-web-security`.

### Ginkgo Test Suite Setup

Every package contains a `*_suite_test.go` file that bootstraps Ginkgo:

```go
package resourceserver_test

import (
    "testing"

    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
)

func TestResourceServer(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "OAuth2 Resource Server Suite")
}
```

### Testing Resource Server with Mock JWTs

```go
var _ = Describe("JwtAuthenticationProvider", func() {
    It("authenticates a valid Bearer token and returns JwtAuthenticationToken", func() {
        km, err := RSAKeyManager{}.New(2048, "rs-test-key")
        Expect(err).NotTo(HaveOccurred())

        encoder := DefaultJwtEncoder{}.New(km)
        now := time.Now()
        claimsSet := JwtClaimsSet{}.New()
        claimsSet.Issuer = "https://auth.example.com"
        claimsSet.Subject = "alice"
        claimsSet.IssuedAt = now
        claimsSet.ExpiresAt = now.Add(30 * time.Minute)
        claimsSet.Claims["scope"] = "read write admin"

        token, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claimsSet})
        Expect(err).NotTo(HaveOccurred())

        decoder := NimbusJwtDecoder{}.New(km).WithIssuer("https://auth.example.com")
        provider := JwtAuthenticationProvider{}.New(decoder)

        bearerToken := BearerTokenAuthenticationToken{}.New(token.TokenValue)
        Expect(provider.Supports(bearerToken)).To(BeTrue())

        auth, authEx := provider.Authenticate(bearerToken)
        Expect(authEx).NotTo(HaveOccurred())
        Expect(auth.IsAuthenticated()).To(BeTrue())
        Expect(auth.GetName()).To(Equal("alice"))

        var authNames []string
        for _, a := range auth.GetAuthorities() {
            authNames = append(authNames, a.Authority())
        }
        Expect(authNames).To(ConsistOf("SCOPE_read", "SCOPE_write", "SCOPE_admin"))
    })
})
```

### Testing Filters with `MockSecurityHandler`

Use `MockSecurityHandler` from `github.com/BeamFoundry/rays-web-security/pkg/testing` to test HTTP filter behavior without starting a full HTTP server:

```go
var _ = Describe("BearerTokenAuthenticationFilter", func() {
    It("authenticates request and populates SecurityContext when Bearer token is present", func() {
        u, err := url.Parse("https://api.example.com/resource")
        Expect(err).NotTo(HaveOccurred())
        
        handler := NewMockSecurityHandler(HttpMethods.GET, u)
        handler.SetHeader("Authorization", "Bearer valid-token")

        chainEx := filter.Authenticate(handler)
        Expect(chainEx).NotTo(BeNil())
        Expect(chainEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))

        ctxAuth := contextHolder.GetContext().GetAuthentication()
        Expect(ctxAuth).NotTo(BeNil())
        Expect(ctxAuth.GetName()).To(Equal("bob"))
    })
})
```

### In-Memory Repositories

For testing without requiring external databases:
- `InMemoryClientRegistrationRepository{}.New(...)`: Pre-register mock OAuth2 providers (`google`, `github`, etc.).
- `InMemoryOAuth2AuthorizedClientService{}.New()`: Store and inspect tokens for authorized clients.
- `SessionAuthorizationRequestRepository{}.New()`: Persist and inspect PKCE state in mock sessions.
- `InMemoryRegisteredClientRepository{}.New(...)`: Register OAuth2 clients for testing Authorization Server.
- `InMemoryOAuth2AuthorizationService{}.New()`: Store and inspect authorization codes, access tokens, and refresh tokens.

### Security Attack Testing & Race Prevention

Given the security-critical nature of OAuth 2.0 / OpenID Connect implementations, `rays-web-security-oauth2` includes dedicated vulnerability and attack defense suites:

1. **JWT Security Attack Test Suite (`pkg/jwt/security_attack_test.go`):**
   - **Algorithm Confusion Attacks:** Rejection of `alg: "none"`, `"NONE"`, mixed casing, and missing `alg` headers.
   - **RSA-to-HMAC Key Confusion Attacks:** Rejection of tokens signed with symmetric `HS256` using the RSA public key's modulus bytes ($N$) as HMAC secret.
   - **Signature Stripping Attacks:** Rejection of unsigned 2-part tokens (`header.payload`) and empty signatures (`header.payload.`).
   - **Signature Tampering Attacks:** Single-bit alteration detection.
   - **Header Injection & Path Traversal:** Safe handling of malicious `kid` headers (`../../../../etc/passwd`, SQL injection strings, XSS payloads).
   - **Time Boundary Verification:** Strict enforcement of `exp` and `nbf` against allowable clock skew.
2. **Authorization Code Single-Use & Replay Race Prevention (`pkg/server/concurrency_test.go`):**
   - Enforces synchronized atomic single-use exchange of authorization codes in `OAuth2AuthorizationService` (RFC 6749 §4.1.2).
   - **High Concurrency Race Test:** 50 simultaneous goroutines released at the exact same millisecond attempting to exchange the same authorization code.
   - Exactly **1 request succeeds** (HTTP 200) and **49 requests are cleanly rejected** with `invalid_grant` (HTTP 400).
   - Verified under `go test -race` with **0 data races**.
3. **Native Go Fuzz Testing (`testing.F`):**
   - `FuzzParseUnverified` (`pkg/jwt/jwt_fuzz_test.go`): Robust against malformed inputs and arbitrary byte streams.
   - `FuzzNimbusJwtDecoder` (`pkg/jwt/jwt_fuzz_test.go`): Parser resilience against arbitrary tokens.
   - `FuzzHandleAuthorizeRedirect` (`pkg/server/redirect_fuzz_test.go`): Open redirect vectors, scheme injections, and CRLF payloads.
   - `FuzzBuildAuthorizationURI` (`pkg/login/pkce_fuzz_test.go`): Query parameter escaping and PKCE challenge formatting.

### Running the Test Suites

```bash
# Run all unit tests with coverage
go test -count=1 -cover ./pkg/...

# Run race detector across all packages
go test -race ./pkg/...

# Run Keycloak Testcontainers integration tests
go test -v -count=1 ./test/keycloak/...
```
