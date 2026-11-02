---
title: "Opaque Tokens & Introspection"
weight: 3
---

# Opaque Tokens & Introspection

When your system uses opaque (reference) tokens instead of self-contained JWTs, the Resource Server validates tokens by calling the Authorization Server's **Introspection Endpoint (RFC 7662)**.

---

## 🛰️ How It Works

1. The client sends an opaque Bearer token in the request header.
2. `BearerTokenAuthenticationFilter` extracts the token string.
3. `OpaqueTokenAuthenticationProvider` issues an authenticated POST request to `/oauth2/introspect` with client credentials.
4. The authorization server returns:
   ```json
   {
     "active": true,
     "sub": "user_123",
     "client_id": "client_abc",
     "scope": "read write",
     "exp": 1729000000
   }
   ```
5. If `active` is true, an authenticated principal is registered into the `SecurityContextHolder`.
