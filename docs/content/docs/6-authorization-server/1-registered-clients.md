---
title: "Registered Clients & Grants"
weight: 1
---

# Registered Clients & Grants

A `RegisteredClient` defines the permissions, credentials, and constraints of a client application that requests tokens from the authorization server.

---

## 🛠️ Registering a Client

Use `RegisteredClientBuilder` (or `NewRegisteredClient`) to fluently construct registered clients:

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
    spaClient := RegisteredClientBuilder{}.New("spa-client-1").
        ClientID("my-react-app").
        ClientName("My React App").
        ClientAuthenticationMethod(ClientAuthMethodNone).
        AuthorizationGrantType(GrantTypeAuthorizationCode).
        RedirectURI("http://localhost:3000/callback").
        Scope("openid", "profile", "orders:read").
        RequireProofKey(true). // Enforces PKCE (S256)
        AccessTokenTimeToLive(30 * time.Minute).
        Build()

    // 2. Machine-to-Machine Backend Service
    m2mClient := RegisteredClientBuilder{}.New("m2m-client-2").
        ClientID("billing-worker").
        ClientSecret("worker-super-secret").
        ClientName("Billing Worker").
        ClientAuthenticationMethod(ClientAuthMethodBasic).
        AuthorizationGrantType(GrantTypeClientCredentials).
        Scope("billing:write", "invoices:read").
        AccessTokenTimeToLive(1 * time.Hour).
        Build()

    return InMemoryRegisteredClientRepository{}.New(spaClient, m2mClient)
}
```

---

## 🔒 PKCE Enforcement

Setting `RequireProofKey(true)` (or `RequireProofKey: true` on `RegisteredClient`) guarantees that the authorization server strictly enforces RFC 7636 (PKCE). Any authorization request without a `code_challenge` or with a method other than `S256` is rejected immediately.
