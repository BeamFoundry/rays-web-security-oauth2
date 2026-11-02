---
title: "Key Management & Token Issuance"
weight: 3
---

# Key Management & Token Issuance

The Authorization Server issues signed JSON Web Tokens for access tokens and cryptographically random tokens for refresh tokens.

---

## 🔑 Key Management with `RSAKeyManager`

`RSAKeyManager` generates and manages RSA key pairs:

```go
package configurations

import (
    . "github.com/BeamFoundry/rays/pkg/core"
    . "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
)

type KeyConfig struct {
    Configuration
}

func (this *KeyConfig) JWKSource() JWKSource {
    km, err := RSAKeyManager{}.New(2048, "auth-key-primary")
    if err != nil {
        panic(err)
    }
    return km
}
```

---

## 🎟️ The `JwtOAuth2TokenGenerator` & `JwxJwtEncoder`

Token generation maps the authorization context to a signed JWT using either the built-in RSA signer or the powerful `JwxJwtEncoder` (`github.com/lestrrat-go/jwx/v3`):

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
> The `/oauth2/jwks` endpoint serves the public keys from the separately configured `JWKSource` Beam, **not** directly from `JwxJwtEncoder`. When configuring a custom token encoder (such as the ES256, EdDSA, or PS256 examples above), ensure that your registered `JWKSource` and the encoder share the exact same underlying key material and key identifier (`kid`) so that client applications and Resource Servers can successfully verify token signatures.
