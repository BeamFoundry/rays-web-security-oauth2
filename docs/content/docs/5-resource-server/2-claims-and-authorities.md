---
title: "Claims & Authority Conversion"
weight: 2
---

# Claims & Authority Conversion

Once a JWT is decoded and verified, its claims must be translated into `GrantedAuthority` objects that `rays-web-security` authorization policies (`HasAuthority`, `HasRole`) can evaluate.

---

## 🔄 `JwtAuthenticationConverter`

The default converter searches standard claim attributes (`scope`, `scp`, `authorities`, `roles`) and prefixes them with `SCOPE_`:

*   Claim `"scope": "read write"` yields:
    *   `Authority("SCOPE_read")`
    *   `Authority("SCOPE_write")`

---

## 🎨 Customizing the Converter

You can customize how authorities are extracted:

```go
converter := DefaultJwtAuthenticationConverter{}.New().
    WithPrincipalClaimName("preferred_username").
    WithAuthorityPrefix("ROLE_")

provider := JwtAuthenticationProvider{}.New(decoder).
    WithConverter(converter)
```

Now, endpoint policies can enforce:

```go
AuthorizedHTTPRequests().
    Paths("/api/orders/**").HasAuthority("SCOPE_read").
    Paths("/api/admin/**").HasRole("ADMIN"). // Expects "ROLE_ADMIN"
    AnyRequest().Authenticated()
```
