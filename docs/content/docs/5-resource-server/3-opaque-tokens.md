---
title: "Opaque Tokens & Introspection"
weight: 3
---

# Opaque Tokens & Introspection

When your system uses opaque (reference) tokens instead of self-contained JWTs, the Resource Server validates tokens by calling the Authorization Server's **Introspection Endpoint (RFC 7662)**.

---

## ⚠️ Resource Server Support Status

> [!NOTE]
> Resource-server support for opaque tokens via `OpaqueTokenAuthenticationProvider` is currently unavailable. Opaque token introspection flow on the Resource Server side is planned for a future release; currently, Resource Server token validation is supported via stateless JWT verification (`JwtAuthenticationProvider` with `JwtDecoder`).

The Authorization Server provides an RFC 7662 introspection endpoint at `/oauth2/introspect` for clients to query token status. Resource Server integration using an introspection provider will be documented once the provider and its registration exist.

