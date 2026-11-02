---
title: "BeamFoundry Rays OAuth2"
type: docs
---

# BeamFoundry Rays OAuth2 🔐

**Rays OAuth2** brings the comprehensive, enterprise-grade architecture of **Spring Security OAuth2** to Go and the Rays framework.

Designed as the dedicated OAuth 2.0 and OpenID Connect 1.0 extension for [`github.com/BeamFoundry/rays-web-security`](https://rays.bfdy.dev/rays-web-security/), it plugs directly into standard security interfaces (`SecurityFilter`, `SecurityEndpointRegistration`, `AuthenticationManager`, `AuthenticationProvider`, and `SecurityContextHolder`).

It delivers four complete, production-ready modules:

1. **OAuth2 Login:** Federated authentication (SSO) with OpenID Connect (OIDC) & OAuth2 providers (Google, GitHub, Keycloak, Okta) using the Authorization Code grant with PKCE.
2. **OAuth2 Client:** Managing client registrations, handling token refresh, client credentials machine-to-machine calls, and accessing protected external APIs.
3. **OAuth2 Resource Server:** Protecting HTTP APIs using Bearer tokens (RFC 6750) with cryptographic JWT verification (JWK sets, key rotation, claims validation) or Opaque Token Introspection (RFC 7662).
4. **OAuth2 Authorization Server:** Full OAuth 2.1 / OIDC 1.0 Authorization Server that issues signed JWT access tokens, refresh tokens, JWK sets, and discovery metadata.

---

### 📚 Documentation Chapters

1. [Introduction & Architecture](/rays-web-security-oauth2/docs/1-introduction/)
2. [Quickstart & Setup](/rays-web-security-oauth2/docs/2-quickstart/)
3. [OAuth2 Login (SSO & OIDC)](/rays-web-security-oauth2/docs/3-oauth2-login/)
4. [OAuth2 Client (API Consumption)](/rays-web-security-oauth2/docs/4-oauth2-client/)
5. [OAuth2 Resource Server (Bearer & JWT)](/rays-web-security-oauth2/docs/5-resource-server/)
6. [OAuth2 Authorization Server](/rays-web-security-oauth2/docs/6-authorization-server/)
7. [Fluent Configuration DSL](/rays-web-security-oauth2/docs/7-configuration-dsl/)
8. [Testing](/rays-web-security-oauth2/docs/8-testing/)
