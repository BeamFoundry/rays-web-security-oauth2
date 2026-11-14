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

## ⚖️ Choosing a `JwtDecoder`: `JwxJwtDecoder` vs `NimbusJwtDecoder`

`rays-web-security-oauth2` provides two `JwtDecoder` implementations with complementary strengths:

| Feature / Use Case | `JwxJwtDecoder` | `NimbusJwtDecoder` |
| :--- | :--- | :--- |
| **Key Input** | Remote `jwks_uri` (`NewWithRemoteJWKS`) or `jwx/v3` `jwk.Set` (`NewWithKeySet`) | `JWKSource` interface (e.g., `RSAKeyManager`, custom PEM/KMS source) |
| **Remote JWKS & Rotation** | Built-in (`jwk.Cache` + `httprc/v3` + `singleflight`) | Not built-in (delegates key lookup to `JWKSource`) |
| **Standard Algorithms** | `RS256-512`, `PS256-512`, `ES256-512`, `EdDSA`, `HS256-512` | `RS256-512`, `PS256-512`, `ES256-512`, `EdDSA`, `HS256-512` (Go stdlib only) |
| **Non-Stdlib Curves/Algs** | `ES256K` (secp256k1), `Ed448` via `jwx/v3` | Unsupported (`UnsupportedAlgorithmError`) |
| **Audience Validation** | Variadic `WithAudience(aud ...string)` (OR-match) | Variadic `WithAudience(aud ...string)` (OR-match) |
| **Runtime Lifecycle** | Spawns background JWKS refresh goroutines for remote JWKS | Stateless & synchronous per `Decode` call (zero external deps) |
| **Error Granularity** | `JWKSFetchError`, `JwtParseError`, `JwtValidationError` | Granular (`AlgorithmMismatchError`, `UnknownKeyIdError`, `SignatureVerificationError`, `JwtExpiredError`, `JwtNotYetValidError`, `InvalidIssuerError`, `InvalidAudienceError`) |

**Rule of thumb:**
*   Use **`JwxJwtDecoder`** when verifying tokens against an external Identity Provider's remote JWKS endpoint (`jwks_uri`) with automatic key rotation, when verifying from a `jwx` `jwk.Set`, or when you need non-stdlib algorithms like `ES256K` / `Ed448`.
*   Use **`NimbusJwtDecoder`** when verifying tokens against an in-process `JWKSource` (such as `RSAKeyManager`, shared HMAC secrets, or a custom PEM/KMS-backed `JWKSource`), when you want zero background goroutines and zero third-party crypto dependencies, or when you want granular error names in unit/integration tests.

---

## 🔑 `JwxJwtDecoder` (Powered by `lestrrat-go/jwx/v3`)

For external Identity Providers and remote JWKS endpoints, `JwxJwtDecoder` integrates with **`github.com/lestrrat-go/jwx/v3`** and supports all standard JWS algorithms (`RS256-512`, `PS256-512`, `ES256-512`, `EdDSA`, `HS256-512`, plus `ES256K` / `Ed448`).

### 1. Remote JWKS Endpoint (with Key Rotation)

When connecting to an external Identity Provider (Keycloak, Auth0, Okta, Google), the decoder automatically fetches, caches, and rotates public keys from the provider's `jwks_uri`:

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

// Automatically fetches and verifies keys from remote JWKS.
func (this *DecoderConfig) JwtDecoder() JwtDecoder {
    return NewJwxJwtDecoderWithRemoteJWKS("https://auth.company.com/oauth2/jwks").
        WithIssuer("https://auth.company.com").
        WithAudience("my-api-audience", "my-api-v2").
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

### 2. Static JWK Set

For internal services or testing with a preloaded `jwk.Set`:

```go
func (this *DecoderConfig) LocalJwtDecoder(set jwk.Set) JwtDecoder {
    return NewJwxJwtDecoderWithKeySet(set).
        WithIssuer("https://auth.local").
        WithAudience("internal-api")
}
```

---

## 🛡️ `NimbusJwtDecoder` (`JWKSource` & Go Stdlib)

`NimbusJwtDecoder` verifies tokens directly against a [`JWKSource`](../6-authorization-server/3-token-issuance/) using only the Go standard library (`RS256-512`, `PS256-512`, `ES256-512`, `EdDSA`, and `HS256-512`):

```go
func (this *DecoderConfig) NimbusDecoder(
    that struct {
        jwkSource JWKSource `@:"Inject"`
    },
) JwtDecoder {
    return NewNimbusJwtDecoder(that.jwkSource).
        WithIssuer("https://auth.company.com").
        WithAudience("my-api-audience", "my-api-v2").
        WithClockSkew(60 * time.Second)
}
```

---

## ⚙️ Externalizing Decoder Settings with `ConfigurationProperties`

Instead of hardcoding endpoints, issuers, or allowed audiences, bind them from your application configuration (`application.yaml`) using Rays' [`ConfigurationProperties`](https://rays.bfdy.dev/):

```yaml
security:
  oauth2:
    resourceserver:
      jwksURI: "https://auth.company.com/.well-known/jwks.json"
      issuer: "https://auth.company.com"
      audiences: ["my-api-audience", "my-api-v2"]
      clockSkew: "60s"
```

```go
package configurations

import (
    "time"

    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
)

type ResourceServerJwtProperties struct {
    ConfigurationProperties `Name:"security.oauth2.resourceserver"`

    jwksURI   string        `validate:"required,url"`
    issuer    string        `validate:"required,url"`
    audiences []string      `validate:"gt=0,dive,required"`
    clockSkew time.Duration `validate:"gte=0"`
}

var _, _ = any(&ResourceServerJwtProperties{}).(Stereotype)

func (this *DecoderConfig) JwtDecoder(
    that struct {
        props *ResourceServerJwtProperties `@:"Inject"`
    },
) JwtDecoder {
    return NewJwxJwtDecoderWithRemoteJWKS(that.props.jwksURI).
        WithIssuer(that.props.issuer).
        WithAudience(that.props.audiences...).
        WithClockSkew(that.props.clockSkew)
}
```

> [!NOTE]
> Rays `ConfigurationProperties` binds **private (lowercase)** struct fields by exact case match and validates them using `go-playground/validator/v10` tags. Inject the properties struct into a `Configuration` or `Service` in the same package.

---

### Validations Performed

Both `JwxJwtDecoder` and `NimbusJwtDecoder` enforce:

1. **Cryptographic Signature:** Verifies the token's signature (`RS256-512`, `PS256-512`, `ES256-512`, `EdDSA`, or `HS256-512`) against the key matching `kid`, rejecting `alg: "none"` and mismatched key types or EC curves.
2. **Expiration (`exp`):** Requires a valid positive numeric `exp` claim and rejects tokens past expiration plus clock skew (60s default).
3. **Not Before (`nbf`):** When present, requires a valid positive numeric `nbf` claim and rejects tokens not yet active within clock skew.
4. **Issuer (`iss`):** When `WithIssuer` is configured, ensures `iss` matches the expected issuer URL.
5. **Audience (`aud`):** When `WithAudience` is configured, ensures at least one configured audience matches the token's `aud` claim.
