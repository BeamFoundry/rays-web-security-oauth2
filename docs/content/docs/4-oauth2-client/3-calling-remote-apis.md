---
title: "Calling Remote APIs"
weight: 3
---

# Calling Remote APIs

Once authorized, your application can consume remote APIs with automatic Bearer token injection:

```go
package services

import (
    "net/http"

    . "github.com/BeamFoundry/rays/pkg/lang"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
)

type RemoteApiClient struct {
    clientManager OAuth2AuthorizedClientManager
    httpClient    *http.Client
}

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
