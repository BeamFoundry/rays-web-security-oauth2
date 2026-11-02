---
title: "Calling Remote APIs"
weight: 3
---

# Calling Remote APIs

Once authorized, your application can consume remote APIs with automatic Bearer token injection:

```go
package services

import (
    "fmt"
    "net/http"
    "time"

    . "github.com/BeamFoundry/rays/pkg/lang"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
)

type RemoteApiClient struct {
    clientManager OAuth2AuthorizedClientManager
    httpClient    *http.Client
}

func NewRemoteApiClient(clientManager OAuth2AuthorizedClientManager) *RemoteApiClient {
    return &RemoteApiClient{
        clientManager: clientManager,
        httpClient: &http.Client{
            Timeout: 10 * time.Second,
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                if len(via) >= 10 {
                    return fmt.Errorf("stopped after 10 redirects")
                }
                if req.URL.Scheme != "https" {
                    return fmt.Errorf("redirect target must use HTTPS: %s", req.URL.String())
                }
                return nil
            },
        },
    }
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
