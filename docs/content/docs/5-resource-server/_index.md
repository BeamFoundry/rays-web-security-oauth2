---
title: "5. Resource Server"
weight: 5
bookCollapseSection: false
---

# OAuth2 Resource Server

An **OAuth2 Resource Server** protects HTTP endpoints by validating incoming OAuth 2.0 Bearer tokens (RFC 6750) included in request headers.

Modeled after Spring Security's `oauth2ResourceServer()`, `rays-web-security-oauth2` extracts the Bearer token, validates it via **stateless JWT verification** or **opaque token introspection (RFC 7662)**, maps claims to `GrantedAuthority` slices, and populates the `SecurityContextHolder`.

---

## ⚡ The Request Lifecycle

```
1. Client requests protected API:
   GET /api/orders
   Authorization: Bearer eyJhbGciOiJSUzI1Ni...

2. BearerTokenAuthenticationFilter resolves token from Authorization header.

3. Creates unauthenticated BearerTokenAuthenticationToken.

4. AuthenticationManager delegates to JwtAuthenticationProvider.

5. JwtDecoder verifies signature using JWK Set (public keys) and checks:
   - exp (expiration with configurable clock skew)
   - nbf (not before)
   - iss (matches expected issuer)
   - aud (matches expected audience)

6. JwtAuthenticationConverter maps scopes to GrantedAuthorities:
   - "read write" -> [SCOPE_read, SCOPE_write]

7. Authenticated JwtAuthenticationToken placed into SecurityContextHolder.

8. Downstream endpoint executes with principal identity.
```

---

## 📂 Subtopics

1. [JWT Validation & JWK Sets](/rays-web-security-oauth2/docs/5-resource-server/1-jwt-validation/)
2. [Claims & Authority Conversion](/rays-web-security-oauth2/docs/5-resource-server/2-claims-and-authorities/)
3. [Opaque Tokens & Introspection](/rays-web-security-oauth2/docs/5-resource-server/3-opaque-tokens/)
