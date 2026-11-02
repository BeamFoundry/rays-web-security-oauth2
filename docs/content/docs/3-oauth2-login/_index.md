---
title: "3. OAuth2 Login"
weight: 3
bookCollapseSection: false
---

# OAuth2 Login (SSO & OpenID Connect)

**OAuth2 Login** provides web applications with the ability to have users log in using their existing accounts at an external OAuth 2.0 or OpenID Connect 1.0 provider (such as Google, GitHub, Keycloak, or Okta).

Modeled after Spring Security's `oauth2Login()`, this feature automates the entire Authorization Code grant lifecycle, including **Proof Key for Code Exchange (PKCE)** and state parameter validation.

---

## 🔄 The Authentication Flow

```
1. Unauthenticated request to protected route
   └─► Redirects to /oauth2/authorization/{registrationId}

2. Authorization Request Initiation
   └─► Generates cryptographically secure State, Nonce, and PKCE (code_verifier & code_challenge S256)
   └─► Saves OAuth2AuthorizationRequest into HTTP session
   └─► 302 Redirect to Provider's Authorization Endpoint

3. User signs in & consents at Identity Provider
   └─► Provider redirects back to /login/oauth2/code/{registrationId}?code=xyz&state=abc

4. Callback Processing & Token Exchange
   └─► OAuth2LoginAuthenticationFilter validates state matches session
   └─► AuthenticationManager delegates to OAuth2LoginAuthenticationProvider
   └─► POST {tokenUri} exchanging code + code_verifier for access_token and id_token
   └─► Decodes OIDC id_token or calls {userInfoUri}
   └─► Instantiates OAuth2User / OidcUser with GrantedAuthorities
   └─► Saves OAuth2AuthenticationToken into SecurityContextHolder & session
   └─► 302 Redirect to user's originally requested URL
```

---

## 📂 Subtopics

1. [Client Registration & Providers](/rays-web-security-oauth2/docs/3-oauth2-login/1-client-registration/)
2. [User Services & Claims Mapping](/rays-web-security-oauth2/docs/3-oauth2-login/2-user-services/)
3. [Login Filter & Technical Endpoints](/rays-web-security-oauth2/docs/3-oauth2-login/3-filter-and-endpoints/)
