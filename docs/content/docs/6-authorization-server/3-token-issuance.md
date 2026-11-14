---
title: "Key Management & Token Issuance"
weight: 3
---

# Key Management & Token Issuance

The Authorization Server issues signed JSON Web Tokens for access tokens and cryptographically random tokens for refresh tokens.

---

## 🔑 Key Management Approaches

Choose the key management strategy that fits your environment:

| Approach | Key Lifecycle | Best For |
| :--- | :--- | :--- |
| **`RSAKeyManager`** | Generates an ephemeral 2048-bit+ RSA keypair in memory on startup | Local development, quickstarts, and unit/integration tests |
| **Rays `ConfigurationProperties` + Persistent Keys** | Loads persistent RSA / ECDSA / Ed25519 keys from PEM files or secret-injected config | Single-instance or multi-replica production services where tokens must survive restarts |
| **Custom `JWKSource` (DB / KMS / Vault)** | Resolves active signing keys and historical verification keys dynamically by `kid` | Zero-downtime key rotation and centralized KMS/HSM signing |

---

### 1. Ephemeral Keys for Development & Testing (`RSAKeyManager`)

`RSAKeyManager` generates and manages an in-memory RSA key pair (`RS256`):

```go
package configurations

import (
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
)

type KeyConfig struct {
    Configuration
}

var _, _ = any(&KeyConfig{}).(Stereotype)

func (this *KeyConfig) JWKSource() (JWKSource, error) {
    return RSAKeyManager{}.New(2048, "auth-key-primary")
}
```

> [!WARNING]
> Because `RSAKeyManager` generates a new keypair every time the process starts, previously issued tokens will fail verification after a restart or across multiple replicas. Use persistent externalized keys in production.

---

### 2. Persistent ECDSA Keys with Rays `ConfigurationProperties` (Recommended for Production)

In production, externalize key paths, `kid`, and algorithm settings in `application.yaml` and bind them using Rays' `ConfigurationProperties`:

```yaml
security:
  oauth2:
    jwt:
      keyID: "auth-key-2026-01"
      algorithm: "ES256"
      privateKeyPath: "/etc/secrets/oauth2/ec-private.pem"
```

> [!IMPORTANT]
> Rays `ConfigurationProperties` binds private fields using **exact-case** key names (`keyID`, `privateKeyPath`), and `AddOverride` only overrides keys that already exist in loaded configuration. A default `APP_` / `RAYS_` environment-variable loop lowercases variable names (`APP_SECURITY_OAUTH2_JWT_KEYID` becomes `app.security.oauth2.jwt.keyid`), keeps the `app.` / `rays.` prefix, and **cannot** bind camelCase fields like `keyID` or `privateKeyPath` on its own. For environment-only deployments without `application.yaml`, map environment variables explicitly to the exact property names during container bootstrap:
>
> ```go
> ctx := rays.ApplicationContext()
> if err := ctx.LoadDefaultConfigAt(map[string]any{
>     "keyID":          os.Getenv("OAUTH2_JWT_KEY_ID"),
>     "algorithm":      os.Getenv("OAUTH2_JWT_ALGORITHM"),
>     "privateKeyPath": os.Getenv("OAUTH2_JWT_PRIVATE_KEY_PATH"),
> }, "security.oauth2.jwt"); err != nil {
>     panic(err)
> }
> ```

The example below binds an ECDSA keypair (`ES256`, `ES384`, or `ES512`). To issue RSA (`RS256-512`, `PS256-512`) or Ed25519 (`EdDSA`) tokens instead, load `*rsa.PrivateKey` or `ed25519.PrivateKey` and publish the matching `RSA` or `OKP` JWK in `GetJWKSet()`:

```go
package configurations

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "fmt"
    "os"

    "github.com/lestrrat-go/jwx/v3/jwa"
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays/pkg/lang"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
)

// 1. Bind and validate ECDSA configuration properties (fields must be lowercase/private).
type JwtKeyProperties struct {
    ConfigurationProperties `Name:"security.oauth2.jwt"`

    keyID          string `validate:"required"`
    algorithm      string `validate:"required,oneof=ES256 ES384 ES512"`
    privateKeyPath string `validate:"required,file"`
}

var _, _ = any(&JwtKeyProperties{}).(Stereotype)

// 2. Implement JWKSource backed by the loaded EC keypair so /oauth2/jwks and NimbusJwtDecoder share it.
type StaticECJWKSource struct {
    kid  string
    alg  string
    priv *ecdsa.PrivateKey
}

func (this *StaticECJWKSource) GetSigningKey() (kid string, privateKey any, alg string, err Error) {
    return this.kid, this.priv, this.alg, nil
}

func (this *StaticECJWKSource) GetVerificationKey(kid string) (publicKey any, alg string, err Error) {
    if kid != "" && kid != this.kid {
        return nil, "", NewError("UnknownKeyIdError", "unknown key id: "+kid)
    }
    return &this.priv.PublicKey, this.alg, nil
}

func (this *StaticECJWKSource) GetJWKSet() (*JWKSet, Error) {
    pubBytes, err := this.priv.PublicKey.Bytes()
    if err != nil {
        return nil, NewErrorFrom(err)
    }
    coordSize := (this.priv.Curve.Params().BitSize + 7) / 8
    return &JWKSet{
        Keys: []JWK{{
            Kty: "EC",
            Use: "sig",
            Alg: this.alg,
            Kid: this.kid,
            Crv: this.priv.Curve.Params().Name,
            X:   base64.RawURLEncoding.EncodeToString(pubBytes[1 : 1+coordSize]),
            Y:   base64.RawURLEncoding.EncodeToString(pubBytes[1+coordSize:]),
        }},
    }, nil
}

// 3. Register JWKSource and JwtEncoder beans; returning error fails startup cleanly if key loading or curve matching fails.
type ProductionKeyConfig struct {
    Configuration
}

var _, _ = any(&ProductionKeyConfig{}).(Stereotype)

func (this *ProductionKeyConfig) JWKSource(
    that struct {
        props *JwtKeyProperties `@:"Inject"`
    },
) (JWKSource, error) {
    pemBytes, err := os.ReadFile(that.props.privateKeyPath)
    if err != nil {
        return nil, err
    }
    block, _ := pem.Decode(pemBytes)
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM private key from %s", that.props.privateKeyPath)
    }
    parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }
    ecPriv, ok := parsed.(*ecdsa.PrivateKey)
    if !ok {
        return nil, fmt.Errorf("expected *ecdsa.PrivateKey, got %T", parsed)
    }
    expectedCurve := map[string]elliptic.Curve{
        AlgES256: elliptic.P256(),
        AlgES384: elliptic.P384(),
        AlgES512: elliptic.P521(),
    }[that.props.algorithm]
    if expectedCurve == nil || ecPriv.Curve != expectedCurve {
        return nil, fmt.Errorf("EC key curve %s does not match configured algorithm %s", ecPriv.Curve.Params().Name, that.props.algorithm)
    }
    return &StaticECJWKSource{
        kid:  that.props.keyID,
        alg:  that.props.algorithm,
        priv: ecPriv,
    }, nil
}

func (this *ProductionKeyConfig) JwtEncoder(
    that struct {
        jwkSource JWKSource `@:"Inject"`
    },
) (JwtEncoder, error) {
    kid, privKey, algName, err := that.jwkSource.GetSigningKey()
    if err != nil {
        return nil, err
    }
    alg, ok := jwa.LookupSignatureAlgorithm(algName)
    if !ok {
        return nil, fmt.Errorf("unsupported signature algorithm: %s", algName)
    }
    return NewJwxJwtEncoder(privKey, alg, kid), nil
}
```

When hydrating verification keys from serialized JWK JSON (for example, in a custom `JWKSource` backed by a database or secret manager), `pkg/jwt` also provides stdlib JWK parsers:
*   `ParseRSAPublicKeyFromJWK(jwk *JWK) (*rsa.PublicKey, Error)`
*   `ParseECPublicKeyFromJWK(jwk *JWK) (*ecdsa.PublicKey, Error)` (`P-256`, `P-384`, `P-521`)
*   `ParseEd25519PublicKeyFromJWK(jwk *JWK) (ed25519.PublicKey, Error)` (`OKP` / `Ed25519`)

---

## 🎟️ The `JwtOAuth2TokenGenerator` & `JwxJwtEncoder`

Token generation maps the authorization context to a signed JWT using either `DefaultJwtEncoder` (for `RS256` / `HS256` from a `JWKSource`) or `JwxJwtEncoder` (`github.com/lestrrat-go/jwx/v3`):

1. **Header:** Configured with `typ: "JWT"`, `alg: "..."`, and `kid: "..."`.
2. **Standard Claims:** Injects `iss`, `sub`, `aud`, `exp`, `iat`, and `jti`.
3. **Custom Claims:** Injects `scope: [...]` and `client_id: "..."`.
4. **Refresh Token:** If the client has the `refresh_token` grant type, generates a cryptographically secure random token (32 bytes base64url).

### Supporting Multiple Signature Algorithms with `JwxJwtEncoder`

Using `JwxJwtEncoder`, you can sign access tokens with any cryptographic algorithm:

```go
// 1. ECDSA P-256 (ES256)
encoder := JwxJwtEncoder{}.New(ecdsaPrivateKey, jwa.ES256(), "key-es256")

// 2. Ed25519 (EdDSA)
encoder := JwxJwtEncoder{}.New(ed25519PrivateKey, jwa.EdDSA(), "key-eddsa")

// 3. RSA-PSS (PS256)
encoder := JwxJwtEncoder{}.New(rsaPrivateKey, jwa.PS256(), "key-ps256")
```

> [!IMPORTANT]
> The `/oauth2/jwks` endpoint serves the public keys from the separately configured `JWKSource` Beam, **not** directly from `JwxJwtEncoder`. When configuring a custom token encoder (such as the ES256, EdDSA, or PS256 examples above), ensure that your registered `JWKSource` and the encoder share the exact same underlying key material, key identifier (`kid`), and published algorithm (`alg`) so that client applications, Resource Servers, and `NimbusJwtDecoder` / `JwxJwtDecoder` can verify token signatures.
