---
title: "Client Manager & Providers"
weight: 1
---

# Client Manager & Providers

The `OAuth2AuthorizedClientManager` coordinates the authorization of clients. It receives an `OAuth2AuthorizeRequest` and evaluates its configured `OAuth2AuthorizedClientProvider` list to obtain or refresh tokens.

---

## 🛠️ Usage Example

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

---

## 🔄 Supported Grant Providers

1. **`ClientCredentialsAuthorizedClientProvider`:**
   Sends a POST request to the provider's token endpoint with `grant_type=client_credentials` and Basic or Post authentication.
2. **`RefreshTokenAuthorizedClientProvider`:**
   Inspects the current access token's expiration timestamp. If the token is expired (or within a 60-second clock skew threshold) and a refresh token is present, it automatically requests a new access token and updates the persistence store.
