---
title: "Registered Clients & Grants"
weight: 1
---

# Registered Clients & Grants

A `RegisteredClient` defines the permissions, credentials, and constraints of a client application that requests tokens from the authorization server.

---

## 🛠️ Registering a Client

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
        ID:                         "spa-client-1",
        ClientID:                   "my-react-app",
        ClientName:                 "My React App",
        ClientAuthenticationMethods: []ClientAuthenticationMethod{ClientAuthMethodNone},
        AuthorizationGrantTypes:    []AuthorizationGrantType{GrantTypeAuthorizationCode},
        RedirectURIs:               []string{"http://localhost:3000/callback"},
        Scopes:                     []string{"openid", "profile", "orders:read"},
        RequireProofKey:            true, // Enforces PKCE (S256)
        AccessTokenTimeToLive:      30 * time.Minute,
    }

    // 2. Machine-to-Machine Backend Service
    m2mClient := &RegisteredClient{
        ID:                         "m2m-client-2",
        ClientID:                   "billing-worker",
        ClientSecret:               "worker-super-secret",
        ClientName:                 "Billing Worker",
        ClientAuthenticationMethods: []ClientAuthenticationMethod{ClientAuthMethodBasic},
        AuthorizationGrantTypes:    []AuthorizationGrantType{GrantTypeClientCredentials},
        Scopes:                     []string{"billing:write", "invoices:read"},
        AccessTokenTimeToLive:      1 * time.Hour,
    }

    return InMemoryRegisteredClientRepository{}.New(spaClient, m2mClient)
}
```

---

## 🔒 PKCE Enforcement

Setting `RequireProofKey: true` guarantees that the authorization server strictly enforces RFC 7636 (PKCE). Any authorization request without a `code_challenge` or with a method other than `S256` is rejected immediately.
