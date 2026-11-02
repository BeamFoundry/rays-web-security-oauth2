---
title: "4. OAuth2 Client"
weight: 4
bookCollapseSection: false
---

# OAuth2 Client (API Consumption)

The **OAuth2 Client** module allows your application to act as an OAuth 2.0 client to consume remote protected resources on behalf of an end-user or as the application itself (machine-to-machine).

It abstracts the complexities of:
*   Obtaining access tokens via `client_credentials` grant.
*   Storing and associating tokens with specific users and registrations.
*   Detecting token expiration and automatically renewing tokens via `refresh_token`.

---

## 🏗️ Core Model: `OAuth2AuthorizedClient`

An `OAuth2AuthorizedClient` represents an authorized relationship:

```go
type OAuth2AuthorizedClient struct {
    ClientRegistration *ClientRegistration `json:"client_registration"`
    PrincipalName      string              `json:"principal_name"`
    AccessToken        *OAuth2AccessToken  `json:"access_token"`
    RefreshToken       *OAuth2RefreshToken `json:"refresh_token,omitempty"`
}
```

---

## 📂 Subtopics

1. [Authorized Client Manager & Providers](/rays-web-security-oauth2/docs/4-oauth2-client/1-authorized-client-manager/)
2. [Token Persistence & Client Service](/rays-web-security-oauth2/docs/4-oauth2-client/2-authorized-client-service/)
3. [Calling Remote APIs](/rays-web-security-oauth2/docs/4-oauth2-client/3-calling-remote-apis/)
