---
title: "7. Configuration DSL"
weight: 7
---

# Fluent Configuration DSL

`rays-web-security-oauth2` integrates seamlessly into `rays-web-security` via dedicated fluent configurers and the Go 1.27 generic `With()` method on `HttpSecurityBuilder`.

> **Fluent Extension via `With()` (Go 1.27+):**
> With Go 1.27 generic method support and `rays-web-security` v0.2.0+, `HttpSecurityBuilder` provides:
> ```go
> func (this *HttpSecurityBuilder) With[T HttpSecurityBuilderOption](fn func(*HttpSecurityBuilder) T) T
> ```
> where `HttpSecurityBuilderOption` is:
> ```go
> type HttpSecurityBuilderOption interface {
>     And() *HttpSecurityBuilder
> }
> ```
> Configurer entrypoint functions (`OAuth2Login`, `OAuth2ResourceServer`, `OAuth2AuthorizationServer`) satisfy `func(*HttpSecurityBuilder) T`.
> 
> You no longer need to pre-initialize a local `builder := &HttpSecurityBuilder{}` and manually pass it into configurers. Instead, you can chain directly into `(&HttpSecurityBuilder{}).With(OAuth2Login)`, configure your options fluently, and call `.And()` to return back to the `HttpSecurityBuilder`!

> **Note on Prototype SecurityFilter Injection & Dependency Injection:**
> Custom security filters (`OAuth2LoginAuthenticationFilter`, `BearerTokenAuthenticationFilter`, `OAuth2AuthorizationServerFilter`) are Prototype Beams implementing Rays' `BeamPostConstructWithContext` interface.
> 
> When you invoke `.With(OAuth2Login)...And()`, `.With(OAuth2ResourceServer)...And()`, or `.With(OAuth2AuthorizationServer)...And()`, the configurer registers the filter's configuration into `HttpSecurity` via `AddCustomSecurityFilter(name, cfg)`.
> 
> When the Rays IoC container builds and initializes `HttpSecurity`, it matches the configured filter names, dynamically instantiates the prototype filters, injects their container dependencies (such as `AuthenticationManager`, `SecurityContextHolder`, and registered repositories) directly, and runs `WithContext(ctx)`. This eliminates the need to manually inject and forward `AuthenticationManager` or `SecurityContextHolder` in your `HttpSecurity(...)` configuration method!

---

## 🧩 1. OAuth2 Login Configuration

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

---

## 🛡️ 2. Resource Server (JWT) Configuration

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

---

## 🔑 3. Resource Server (Opaque Token Introspection) Configuration

```go
package config

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays/pkg/core"
)

type OpaqueTokenResourceServerConfig struct {
	Configuration
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
			AnyRequest().Authenticated().
		And().
		Build()
}
```

---

## 🏛️ 4. Authorization Server Configuration

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
		FormLogin().And(). // Required to authenticate users for /oauth2/authorize
		Build()
}
```
