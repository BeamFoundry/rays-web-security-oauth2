---
title: "Opaque Tokens & Introspection"
weight: 3
---

# Opaque Tokens & Introspection

When your architecture uses **opaque (by-reference) tokens** instead of self-contained, signed JWTs, the Resource Server cannot validate tokens locally. Instead, it validates incoming Bearer tokens remotely by calling the Authorization Server's **Introspection Endpoint (RFC 7662)** using `OpaqueTokenAuthenticationProvider`.

---

## ⚡ Architecture & Request Flow

```
1. Client requests protected API:
   GET /api/orders
   Authorization: Bearer 4f9d2a8b-7c1e-43a9-b82d-1092837465ab

2. BearerTokenAuthenticationFilter resolves token from Authorization header.

3. Creates unauthenticated BearerTokenAuthenticationToken.

4. AuthenticationManager delegates to OpaqueTokenAuthenticationProvider.

5. OpaqueTokenIntrospector executes HTTP POST to /oauth2/introspect:
   - Authenticates using Client Credentials (HTTP Basic Auth)
   - Transmits form data: token=<raw_token>&token_type_hint=access_token
   - Validates response: active == true, checks exp (expiration) and nbf (not before)

6. OpaqueTokenAuthenticationConverter converts claims into:
   - OAuth2AuthenticatedPrincipal (principal identity & attributes)
   - GrantedAuthorities (e.g. "read write" -> [SCOPE_read, SCOPE_write])

7. Authenticated BearerTokenAuthentication placed into SecurityContextHolder.

8. Downstream endpoint executes with principal identity.
```

---

## 🔍 The `OpaqueTokenIntrospector` Interface

```go
type OpaqueTokenIntrospector interface {
    Introspect(token string) (OAuth2AuthenticatedPrincipal, Error)
}
```

The default implementation is `NimbusOpaqueTokenIntrospector` (aliased as `DefaultOpaqueTokenIntrospector`), which coordinates the HTTP call, authentication, and JSON deserialization per RFC 7662.

### `NimbusOpaqueTokenIntrospector` Configuration Options

```go
introspector := NewNimbusOpaqueTokenIntrospector(
    "https://auth.example.com/oauth2/introspect",
    "resource-server-client",
    "resource-server-secret",
).
    WithAuthorityPrefix("SCOPE_").                  // Prefix added to scopes (default: "SCOPE_")
    WithAuthoritiesClaims("scope", "roles").         // Claims to search for authorities
    WithPrincipalClaimName("sub").                   // Principal identity claim (fallback: username, client_id)
    WithClockSkew(60 * time.Second).                // Clock skew allowance for exp/nbf checks
    WithTimeout(10 * time.Second).                   // HTTP timeout
    WithHTTPClient(customHTTPClient)                 // Custom *http.Client (optional)
```

---

## 🔐 Authenticated Token: `BearerTokenAuthentication`

Upon successful introspection, `OpaqueTokenAuthenticationProvider` returns a `*BearerTokenAuthentication`:

```go
type BearerTokenAuthentication struct {
    Token       *OAuth2AccessToken `json:"token"`
    Attributes  map[string]any     `json:"attributes"`
    AbstractAuthenticationToken
}
```

- **`GetName()`**: Returns the resolved principal name (from `sub`, `username`, or custom claim).
- **`GetCredentials()`**: Returns the raw token string.
- **`GetPrincipal()`**: Returns the embedded principal stored in `AbstractAuthenticationToken`.
- **`GetAuthorities()`**: Returns the slice of `GrantedAuthority` mapped from `scope` or `roles`.

To access introspected attributes and principal methods, retrieve the principal via `GetPrincipal()` with a type assertion to `OAuth2AuthenticatedPrincipal`:

```go
if principal, ok := auth.GetPrincipal().(OAuth2AuthenticatedPrincipal); ok {
    name := principal.GetName()
    claims := principal.GetAttributes()
    authorities := principal.GetAuthorities()
    _ = name
    _ = claims
    _ = authorities
}
```

---

## 🛠️ Configuration with Rays & Fluent DSL

In the Rays framework, security filter chains are exposed as beans by creating a struct embedding `Configuration` and declaring an `HttpSecurity(...) *HttpSecurity` factory method.

Using the generic `With(OAuth2ResourceServer)` extension on `HttpSecurityBuilder`, you can configure remote token introspection directly into the filter chain.

### 1. Standard Opaque Token Configuration

```go
package config

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays/pkg/core"
)

type OpaqueTokenResourceServerConfig struct {
	Configuration // Rays IoC Configuration component
}

func (this *OpaqueTokenResourceServerConfig) HttpSecurity() *HttpSecurity {
	// AuthenticationManager and SecurityContextHolder are auto-injected by Rays
	return (&HttpSecurityBuilder{}).
		With(OAuth2ResourceServer).
			OpaqueToken(
				"https://auth.example.com/oauth2/introspect",
				"resource-server-client",
				"resource-server-secret",
			).
			Realm("orders-api").
		And().
		Csrf().Disable().
		SessionCreationPolicy().Stateless().
		AuthorizedHTTPRequests().
			Paths("/api/public/**").PermitAll().
			Paths("/api/orders/**").HasAuthority("SCOPE_orders:read").
			Paths("/api/admin/**").HasAuthority("SCOPE_admin").
		And().
		AnyRequest().Authenticated().
		Build()
}
```

### 2. Custom Introspector with Container Dependency Injection

When your introspector requires customized claim mapping, clock skew tolerance, or custom HTTP clients, you can configure it via method-level dependency injection (`that struct { ... }`) or by instantiating it directly:

```go
type CustomOpaqueTokenConfig struct {
	Configuration
}

func (this *CustomOpaqueTokenConfig) HttpSecurity(
	that struct {
		// Automatically injected from the Rays IoC container
		customIntrospector OpaqueTokenIntrospector `@:"Inject"`
	},
) *HttpSecurity {
	return (&HttpSecurityBuilder{}).
		With(OAuth2ResourceServer).
			OpaqueTokenIntrospector(that.customIntrospector).
			Realm("orders-api").
		And().
		SessionCreationPolicy().Stateless().
		AuthorizedHTTPRequests().
			Paths("/api/orders/**").HasAuthority("SCOPE_orders:read").
		And().
		AnyRequest().Authenticated().
		Build()
}
```

Alternatively, configure the introspector inline using `NewNimbusOpaqueTokenIntrospector`:

```go
func (this *CustomOpaqueTokenConfig) HttpSecurity() *HttpSecurity {
	introspector := NewNimbusOpaqueTokenIntrospector(
		"https://auth.example.com/oauth2/introspect",
		"resource-server-client",
		"resource-server-secret",
	).
		WithPrincipalClaimName("preferred_username").
		WithAuthorityPrefix("ROLE_").
		WithAuthoritiesClaims("roles")

	return (&HttpSecurityBuilder{}).
		With(OAuth2ResourceServer).
			OpaqueTokenIntrospector(introspector).
			Realm("orders-api").
		And().
		AuthorizedHTTPRequests().
			Paths("/api/admin/**").HasRole("ADMIN").
		And().
		AnyRequest().Authenticated().
		Build()
}
```
