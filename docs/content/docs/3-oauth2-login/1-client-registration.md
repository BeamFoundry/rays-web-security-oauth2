---
title: "Client Registrations"
weight: 1
---

# Client Registrations

A `ClientRegistration` represents the configuration required to communicate with an external OAuth 2.0 or OpenID Connect 1.0 provider.

It holds client credentials, URLs, scopes, and authentication methods.

---

## 🛠️ Defining a Client Registration

Use `ClientRegistrationBuilder` to fluently construct client registrations:

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

    // 3. Keycloak / Self-Hosted OIDC
    keycloak := ClientRegistrationBuilder{}.New("keycloak").
        ClientID("rays-web-app").
        ClientSecret("keycloak-client-secret").
        AuthorizationGrantType(GrantTypeAuthorizationCode).
        RedirectURI("/login/oauth2/code/keycloak").
        Scope("openid", "profile", "roles").
        AuthorizationURI("https://auth.company.internal/realms/master/protocol/openid-connect/auth").
        TokenURI("https://auth.company.internal/realms/master/protocol/openid-connect/token").
        UserInfoURI("https://auth.company.internal/realms/master/protocol/openid-connect/userinfo").
        JwkSetURI("https://auth.company.internal/realms/master/protocol/openid-connect/certs").
        UserNameAttributeName("preferred_username").
        ClientName("Company SSO").
        Build()

    return InMemoryClientRegistrationRepository{}.New(google, github, keycloak)
}
```

---

## 🗄️ The `ClientRegistrationRepository`

The `ClientRegistrationRepository` acts as the central storage and lookup mechanism:

```go
type ClientRegistrationRepository interface {
    FindByRegistrationID(registrationID string) (*ClientRegistration, Error)
}
```

By default, `InMemoryClientRegistrationRepository` is provided. You can easily implement a database-backed repository (using `rays-orm`) by implementing this single method.
