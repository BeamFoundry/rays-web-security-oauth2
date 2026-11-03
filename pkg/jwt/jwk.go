package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	. "github.com/BeamFoundry/rays/pkg/lang"
)

// AlgRS256 is the RS256 algorithm name
const AlgRS256 = "RS256"

// JWK represents a JSON Web Key (RFC 7517)
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"` // RSA Modulus
	E   string `json:"e,omitempty"` // RSA Exponent
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet represents a set of JSON Web Keys
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKSource provides keys for signing and verification
type JWKSource interface {
	// GetJWKSet returns the public JSON Web Key Set for publishing or verification.
	GetJWKSet() (*JWKSet, Error)
	// GetSigningKey returns the active key ID, private key, and signing algorithm.
	GetSigningKey() (kid string, privateKey any, alg string, err Error)
	// GetVerificationKey returns the verification key and algorithm for the specified key ID: a public key for asymmetric algorithms (such as RS256 or ES256) or a shared secret for symmetric algorithms (such as HS256). Shared secrets must remain confidential.
	GetVerificationKey(kid string) (publicKey any, alg string, err Error)
}

// RSAKeyManager manages an RSA keypair for signing and JWKS publishing
type RSAKeyManager struct {
	mu         *sync.RWMutex
	privateKey *rsa.PrivateKey
	kid        string
	alg        string
}

// New generates a new RSA keypair with the specified bit size (minimum 2048) and key ID.
func (this RSAKeyManager) New(bits int, kid string) (*RSAKeyManager, Error) {
	if bits < 2048 {
		bits = 2048
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, NewError("RSAKeyGenerationError", fmt.Sprintf("failed to generate rsa key: %s", err))
	}
	if kid == "" {
		kid = fmt.Sprintf("k-%d", time.Now().Unix())
	}
	this.mu = &sync.RWMutex{}
	this.privateKey = priv
	this.kid = kid
	this.alg = AlgRS256
	return &this, nil
}

// NewRSAKeyManager generates and returns a new RSAKeyManager.
func NewRSAKeyManager(bits int, kid string) (*RSAKeyManager, Error) {
	return RSAKeyManager{}.New(bits, kid)
}

// GetSigningKey returns the key ID, RSA private key, and signing algorithm (RS256).
//
//nolint:revive // JWKSource interface requires 4 return values
func (this *RSAKeyManager) GetSigningKey() (kid string, privateKey any, alg string, err Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()
	return this.kid, this.privateKey, this.alg, nil
}

// GetVerificationKey returns the RSA public key and algorithm matching the requested key ID.
func (this *RSAKeyManager) GetVerificationKey(kid string) (publicKey any, alg string, err Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()
	if kid != "" && kid != this.kid {
		return nil, "", NewError("UnknownKeyIdError", "unknown key id: "+kid)
	}
	return &this.privateKey.PublicKey, this.alg, nil
}

// GetJWKSet exports the RSA public key as a JSON Web Key Set.
func (this *RSAKeyManager) GetJWKSet() (*JWKSet, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	pub := &this.privateKey.PublicKey
	nBytes := pub.N.Bytes()
	eBytes := make([]byte, 4)
	//nolint:gosec // pub.E is positive RSA exponent
	binary.BigEndian.PutUint32(eBytes, uint32(pub.E))
	// Trim leading zero bytes from E
	for len(eBytes) > 0 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}

	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: this.alg,
		Kid: this.kid,
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	return &JWKSet{Keys: []JWK{jwk}}, nil
}

// DefaultJwtEncoder encodes and signs JWTs using a JWKSource
type DefaultJwtEncoder struct {
	jwkSource JWKSource
}

// New creates a new DefaultJwtEncoder backed by the provided JWKSource.
func (this DefaultJwtEncoder) New(source JWKSource) *DefaultJwtEncoder {
	this.jwkSource = source
	return &this
}

// NewDefaultJwtEncoder creates a new DefaultJwtEncoder backed by the provided JWKSource.
func NewDefaultJwtEncoder(source JWKSource) *DefaultJwtEncoder {
	return DefaultJwtEncoder{}.New(source)
}

// Encode serializes and signs the provided headers and claims using the configured JWKSource.
func (this *DefaultJwtEncoder) Encode(params *JwtEncoderParameters) (*Jwt, Error) {
	kid, privKey, alg, err := this.jwkSource.GetSigningKey()
	if err != nil {
		return nil, err
	}

	headers := map[string]any{
		"typ": "JWT",
		"alg": alg,
		"kid": kid,
	}
	if params.Headers != nil {
		maps.Copy(headers, params.Headers)
	}

	claims := make(map[string]any)
	if params.ClaimsSet != nil {
		cs := params.ClaimsSet
		if cs.Issuer != "" {
			claims["iss"] = cs.Issuer
		}
		if cs.Subject != "" {
			claims["sub"] = cs.Subject
		}
		if len(cs.Audience) > 0 {
			claims["aud"] = cs.Audience
		}
		if !cs.ExpiresAt.IsZero() {
			claims["exp"] = cs.ExpiresAt.Unix()
		}
		if !cs.NotBefore.IsZero() {
			claims["nbf"] = cs.NotBefore.Unix()
		}
		if !cs.IssuedAt.IsZero() {
			claims["iat"] = cs.IssuedAt.Unix()
		}
		if cs.JWTID != "" {
			claims["jti"] = cs.JWTID
		}
		maps.Copy(claims, cs.Claims)
	}

	headerJSON, jsonErr := json.Marshal(headers)
	if jsonErr != nil {
		return nil, NewErrorFrom(jsonErr)
	}
	claimJSON, jsonErr := json.Marshal(claims)
	if jsonErr != nil {
		return nil, NewErrorFrom(jsonErr)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimJSON)

	var sig []byte
	switch alg {
	case AlgRS256:
		rsaKey, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, NewError("InvalidPrivateKeyError", "private key is not *rsa.PrivateKey")
		}
		hashed := sha256.Sum256([]byte(signingInput))
		var rsaErr error
		sig, rsaErr = rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hashed[:])
		if rsaErr != nil {
			return nil, NewError("SignTokenError", fmt.Sprintf("failed to sign token: %s", rsaErr))
		}
	case "HS256":
		secret, ok := privKey.([]byte)
		if !ok {
			return nil, NewError("InvalidSecretKeyError", "secret key is not []byte")
		}
		mac := hmac.New(sha256.New, secret)
		if _, writeErr := mac.Write([]byte(signingInput)); writeErr != nil {
			NewErrorFrom(writeErr).LogError()
		}
		sig = mac.Sum(nil)
	default:
		return nil, NewError("UnsupportedAlgorithmError", "unsupported signing algorithm: "+alg)
	}

	tokenValue := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	var issuedAt, expiresAt time.Time
	if params.ClaimsSet != nil {
		issuedAt = params.ClaimsSet.IssuedAt
		expiresAt = params.ClaimsSet.ExpiresAt
	}

	return NewJwt(tokenValue, issuedAt, expiresAt, headers, claims), nil
}

// NimbusJwtDecoder decodes and verifies JWTs using JWKSource or public key
type NimbusJwtDecoder struct {
	jwkSource JWKSource
	issuer    string
	audience  []string
	skew      time.Duration
}

// New creates a new NimbusJwtDecoder with a default 60-second clock skew.
func (this NimbusJwtDecoder) New(source JWKSource) *NimbusJwtDecoder {
	this.jwkSource = source
	this.skew = 60 * time.Second
	return &this
}

// NewNimbusJwtDecoder creates a new NimbusJwtDecoder backed by the provided JWKSource.
func NewNimbusJwtDecoder(source JWKSource) *NimbusJwtDecoder {
	return NimbusJwtDecoder{}.New(source)
}

// WithIssuer configures the expected "iss" (issuer) claim for token validation.
func (this *NimbusJwtDecoder) WithIssuer(issuer string) *NimbusJwtDecoder {
	this.issuer = issuer
	return this
}

// WithAudience configures one or more expected "aud" (audience) values for token validation.
func (this *NimbusJwtDecoder) WithAudience(aud ...string) *NimbusJwtDecoder {
	this.audience = append(this.audience, aud...)
	return this
}

// WithClockSkew configures the allowable clock skew duration when validating "exp" and "nbf" claims.
func (this *NimbusJwtDecoder) WithClockSkew(skew time.Duration) *NimbusJwtDecoder {
	this.skew = skew
	return this
}

// Decode parses, verifies the cryptographic signature, and validates standard claims of a JWT string.
func (this *NimbusJwtDecoder) Decode(token string) (*Jwt, Error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, NewError("InvalidJwtFormatError", "malformed jwt: must have 3 parts")
	}

	headers, claims, err := ParseUnverified(token)
	if err != nil {
		return nil, err
	}

	kid, _ := headers["kid"].(string)
	alg, _ := headers["alg"].(string)

	pubKey, expectedAlg, err := this.jwkSource.GetVerificationKey(kid)
	if err != nil {
		return nil, err
	}
	if expectedAlg != "" && alg != expectedAlg {
		return nil, NewError("AlgorithmMismatchError", fmt.Sprintf("algorithm mismatch: token has %s, expected %s", alg, expectedAlg))
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, b64Err := base64.RawURLEncoding.DecodeString(parts[2])
	if b64Err != nil {
		return nil, NewError("InvalidSignatureError", fmt.Sprintf("invalid signature base64: %s", b64Err))
	}

	switch alg {
	case AlgRS256:
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, NewError("InvalidPublicKeyError", "public key is not *rsa.PublicKey")
		}
		hashed := sha256.Sum256([]byte(signingInput))
		if verifyErr := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], sigBytes); verifyErr != nil {
			return nil, NewError("SignatureVerificationError", fmt.Sprintf("jwt signature verification failed: %s", verifyErr))
		}
	case "HS256":
		secret, ok := pubKey.([]byte)
		if !ok {
			return nil, NewError("InvalidSecretKeyError", "secret key is not []byte")
		}
		mac := hmac.New(sha256.New, secret)
		if _, writeErr := mac.Write([]byte(signingInput)); writeErr != nil {
			NewErrorFrom(writeErr).LogError()
		}
		expectedSig := mac.Sum(nil)
		if !hmac.Equal(sigBytes, expectedSig) {
			return nil, NewError("SignatureVerificationError", "jwt hmac signature mismatch")
		}
	default:
		return nil, NewError("UnsupportedAlgorithmError", "unsupported algorithm: "+alg)
	}

	now := time.Now()

	// Validate exp: require valid positive numeric exp claim
	expVal, ok := claims["exp"]
	if !ok {
		return nil, NewError("JwtExpiredError", "missing exp claim")
	}

	var expUnix int64
	switch v := expVal.(type) {
	case float64:
		expUnix = int64(v)
	case int64:
		expUnix = v
	case json.Number:
		n, numErr := v.Int64()
		if numErr != nil {
			return nil, NewError("JwtExpiredError", "invalid exp claim: non-numeric")
		}
		expUnix = n
	default:
		return nil, NewError("JwtExpiredError", "invalid exp claim: non-numeric")
	}

	if expUnix <= 0 {
		return nil, NewError("JwtExpiredError", "invalid exp claim: zero or negative")
	}

	expTime := time.Unix(expUnix, 0)
	if now.After(expTime.Add(this.skew)) {
		return nil, NewError("JwtExpiredError", "jwt is expired")
	}

	// Validate nbf
	if nbfVal, ok := claims["nbf"]; ok {
		var nbfUnix int64
		switch v := nbfVal.(type) {
		case float64:
			nbfUnix = int64(v)
		case int64:
			nbfUnix = v
		case json.Number:
			if n, numErr := v.Int64(); numErr != nil {
				NewErrorFrom(numErr).LogError()
			} else {
				nbfUnix = n
			}
		default:
		}
		if nbfUnix > 0 {
			nbfTime := time.Unix(nbfUnix, 0)
			if now.Before(nbfTime.Add(-this.skew)) {
				return nil, NewError("JwtNotYetValidError", "jwt is not yet valid (nbf)")
			}
		}
	}

	// Validate issuer
	if this.issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != this.issuer {
			return nil, NewError("InvalidIssuerError", fmt.Sprintf("invalid issuer: got %v, expected %s", claims["iss"], this.issuer))
		}
	}

	// Validate audience
	if len(this.audience) > 0 {
		var tokenAudiences []string
		switch aud := claims["aud"].(type) {
		case string:
			tokenAudiences = append(tokenAudiences, aud)
		case []any:
			for _, a := range aud {
				if s, ok := a.(string); ok {
					tokenAudiences = append(tokenAudiences, s)
				}
			}
		case []string:
			tokenAudiences = append(tokenAudiences, aud...)
		default:
		}
		matched := false
		for _, expected := range this.audience {
			if slices.Contains(tokenAudiences, expected) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, NewError("InvalidAudienceError", fmt.Sprintf("invalid audience: got %v, expected one of %v", claims["aud"], this.audience))
		}
	}

	var issuedAt, expiresAt time.Time
	if iatVal, ok := claims["iat"].(float64); ok {
		issuedAt = time.Unix(int64(iatVal), 0)
	}
	if expVal, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(expVal), 0)
	}

	return NewJwt(token, issuedAt, expiresAt, headers, claims), nil
}

// ParseRSAPublicKeyFromJWK builds an rsa.PublicKey from JWK n and e
func ParseRSAPublicKeyFromJWK(jwk *JWK) (*rsa.PublicKey, Error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, NewError("InvalidJWKError", fmt.Sprintf("invalid n in jwk: %s", err))
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, NewError("InvalidJWKError", fmt.Sprintf("invalid e in jwk: %s", err))
	}

	var e uint64
	for _, b := range eBytes {
		e = (e << 8) | uint64(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e),
	}, nil
}
