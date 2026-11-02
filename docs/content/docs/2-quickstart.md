---
title: "2. Quickstart & Setup"
weight: 2
---

# Quickstart & Setup

Getting started with **Rays OAuth2** takes just a few lines of configuration using the fluent `HttpSecurityBuilder`.

## 📦 Installation

Add both `rays-web-security` and `rays-web-security-oauth2` to your Go module:

```bash
go get github.com/BeamFoundry/rays-web-security
go get github.com/BeamFoundry/rays-web-security-oauth2
```

---

## ⚡ Quickstart 1: Protecting an API (Resource Server)

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

// 1. Register the JwtAuthenticationProvider as a Beam.
// rays-web-security's AuthenticationManager automatically injects all AuthenticationProvider beans!
func (this *ResourceServerSecurityConfig) JwtAuthenticationProvider(
    that struct {
        decoder JwtDecoder `@:"Inject"`
    },
) AuthenticationProvider {
    return JwtAuthenticationProvider{}.New(that.decoder)
}

// 2. Configure HttpSecurity
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

---

## ⚡ Quickstart 2: Social Login / SSO (OAuth2 Login)

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
            DefaultSuccessURL("/dashboard").
        And().
        AuthorizedHTTPRequests().
            Paths("/", "/login/**", "/static/**").PermitAll().
            AnyRequest().Authenticated().
        And().
        Build()
}
```

---

## 🚀 The Application Entrypoint

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
