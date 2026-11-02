---
title: "JWT Validation & JWK Sets"
weight: 1
---

# JWT Validation & JWK Sets

The primary method for securing APIs in `rays-web-security-oauth2` is stateless JWT validation via `JwtDecoder`.

---

## 🔍 The `JwtDecoder` Interface

```go
type JwtDecoder interface {
    Decode(token string) (*Jwt, Error)
}
```

A decoded `*Jwt` contains verified headers, claims, and timestamps:

```go
type Jwt struct {
    TokenValue string         `json:"token_value"`
    IssuedAt   time.Time      `json:"issued_at"`
    ExpiresAt  time.Time      `json:"expires_at"`
    Headers    map[string]any `json:"headers"`
    Claims     map[string]any `json:"claims"`
}
```

---

## 🔑 `JwxJwtDecoder` (Powered by `lestrrat-go/jwx`)

For production environments, `rays-web-security-oauth2` integrates with **`github.com/lestrrat-go/jwx/v3`** (the Go equivalent of Java's Nimbus JOSE+JWT used by Spring Security).

This provides full RFC 7515/7517/7518/7519 compliance and supports **all** signature algorithms:
*   **RSA:** `RS256`, `RS384`, `RS512`
*   **RSA-PSS:** `PS256`, `PS384`, `PS512`
*   **ECDSA:** `ES256`, `ES384`, `ES512` (P-256, P-384, P-521)
*   **EdDSA:** `Ed25519`
*   **HMAC:** `HS256`, `HS384`, `HS512`

### 1. Remote JWKS Endpoint (with Key Rotation)

When connecting to an external Identity Provider (Keycloak, Auth0, Okta, Google), the decoder automatically fetches and verifies public keys directly from the provider's `jwks_uri`:

```go
package configurations

import (
    "time"

    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays-web-security/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/resourceserver"
)

type DecoderConfig struct {
    Configuration
}

// Automatically fetches and verifies keys from remote JWKS
func (this *DecoderConfig) JwtDecoder() JwtDecoder {
    return JwxJwtDecoder{}.NewWithRemoteJWKS("https://auth.company.com/oauth2/jwks").
        WithIssuer("https://auth.company.com").
        WithAudience("my-api-audience").
        WithClockSkew(60 * time.Second)
}

// Register JwtAuthenticationProvider as a Beam.
// rays-web-security's AuthenticationManager automatically injects all AuthenticationProvider beans!
func (this *DecoderConfig) JwtAuthenticationProvider(
    that struct {
        decoder JwtDecoder `@:"Inject"`
    },
) AuthenticationProvider {
    return JwtAuthenticationProvider{}.New(that.decoder)
}
```

### 2. Static JWK Set or Key Pair

For internal services or testing, you can initialize the decoder with a local `jwk.Set`:

```go
func (this *DecoderConfig) LocalJwtDecoder(set jwk.Set) JwtDecoder {
    return JwxJwtDecoder{}.NewWithKeySet(set).
        WithIssuer("https://auth.local").
        WithAudience("internal-api")
}
```

### Validations Performed

1. **Cryptographic Signature:** Verifies RSA (RS256) or HMAC (HS256) using public keys matching the token's `kid` header.
2. **Expiration (`exp`):** Rejects tokens whose expiration timestamp plus clock skew is in the past.
3. **Not Before (`nbf`):** Rejects tokens that are not yet valid.
4. **Issuer (`iss`):** Ensures the issuing authority matches the expected URL.
5. **Audience (`aud`):** Ensures the token was intended for this specific resource server.
