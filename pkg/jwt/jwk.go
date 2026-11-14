package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	. "github.com/BeamFoundry/rays/pkg/lang"
)

// Supported JWT/JWS signing and verification algorithms.
const (
	// AlgRS256 is the RSASSA-PKCS1-v1_5 using SHA-256 algorithm identifier.
	AlgRS256 = "RS256"
	// AlgRS384 is the RSASSA-PKCS1-v1_5 using SHA-384 algorithm identifier.
	AlgRS384 = "RS384"
	// AlgRS512 is the RSASSA-PKCS1-v1_5 using SHA-512 algorithm identifier.
	AlgRS512 = "RS512"
	// AlgPS256 is the RSASSA-PSS using SHA-256 and MGF1 with SHA-256 algorithm identifier.
	AlgPS256 = "PS256"
	// AlgPS384 is the RSASSA-PSS using SHA-384 and MGF1 with SHA-384 algorithm identifier.
	AlgPS384 = "PS384"
	// AlgPS512 is the RSASSA-PSS using SHA-512 and MGF1 with SHA-512 algorithm identifier.
	AlgPS512 = "PS512"
	// AlgES256 is the ECDSA using P-256 and SHA-256 algorithm identifier.
	AlgES256 = "ES256"
	// AlgES384 is the ECDSA using P-384 and SHA-384 algorithm identifier.
	AlgES384 = "ES384"
	// AlgES512 is the ECDSA using P-521 and SHA-512 algorithm identifier.
	AlgES512 = "ES512"
	// AlgEdDSA is the Edwards-curve Digital Signature Algorithm identifier.
	AlgEdDSA = "EdDSA"
	// AlgHS256 is the HMAC using SHA-256 algorithm identifier.
	AlgHS256 = "HS256"
	// AlgHS384 is the HMAC using SHA-384 algorithm identifier.
	AlgHS384 = "HS384"
	// AlgHS512 is the HMAC using SHA-512 algorithm identifier.
	AlgHS512 = "HS512"
)

var rsaGenerateKey = rsa.GenerateKey

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
	priv, err := rsaGenerateKey(rand.Reader, bits)
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
		Try(func() {
			_, writeErr := mac.Write([]byte(signingInput))
			RaiseNilErr(writeErr)
		}).LogError()
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
	if this.jwkSource == nil {
		return nil, NewError("InvalidJWKSourceError", "jwkSource not configured")
	}

	trimmedToken := strings.TrimSpace(token)
	parts := strings.Split(trimmedToken, ".")
	if len(parts) != 3 {
		return nil, NewError("InvalidJwtFormatError", "malformed jwt: must have 3 parts")
	}

	headers, claims, err := ParseUnverified(trimmedToken)
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

	if verifyErr := verifyJwtSignature(alg, pubKey, []byte(signingInput), sigBytes); verifyErr != nil {
		return nil, verifyErr
	}

	now := time.Now()

	// Validate exp: require valid positive numeric exp claim
	expVal, ok := claims["exp"]
	if !ok {
		return nil, NewError("JwtExpiredError", "missing exp claim")
	}

	expUnix, ok := parseJwtTimestamp(expVal)
	if !ok {
		return nil, NewError("JwtExpiredError", "invalid exp claim: non-numeric")
	}

	if expUnix <= 0 {
		return nil, NewError("JwtExpiredError", "invalid exp claim: zero or negative")
	}

	expTime := time.Unix(expUnix, 0)
	if now.After(expTime.Add(this.skew)) {
		return nil, NewError("JwtExpiredError", "jwt is expired")
	}

	// Validate nbf: when present, require valid positive numeric nbf claim
	if nbfVal, ok := claims["nbf"]; ok {
		nbfUnix, ok := parseJwtTimestamp(nbfVal)
		if !ok {
			return nil, NewError("JwtNotYetValidError", "invalid nbf claim: non-numeric")
		}
		if nbfUnix <= 0 {
			return nil, NewError("JwtNotYetValidError", "invalid nbf claim: zero or negative")
		}
		nbfTime := time.Unix(nbfUnix, 0)
		if now.Before(nbfTime.Add(-this.skew)) {
			return nil, NewError("JwtNotYetValidError", "jwt is not yet valid (nbf)")
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
	if iatVal, ok := claims["iat"]; ok {
		if iatUnix, ok := parseJwtTimestamp(iatVal); ok && iatUnix > 0 {
			issuedAt = time.Unix(iatUnix, 0)
		}
	}
	expiresAt = expTime

	return NewJwt(trimmedToken, issuedAt, expiresAt, headers, claims), nil
}

// ParseRSAPublicKeyFromJWK builds an rsa.PublicKey from JWK n and e
func ParseRSAPublicKeyFromJWK(jwk *JWK) (*rsa.PublicKey, Error) {
	if jwk == nil {
		return nil, NewError("InvalidJWKError", "jwk must not be nil")
	}
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

// ParseECPublicKeyFromJWK builds and validates an ecdsa.PublicKey from JWK crv, x, and y fields.
func ParseECPublicKeyFromJWK(jwk *JWK) (*ecdsa.PublicKey, Error) {
	if jwk == nil {
		return nil, NewError("InvalidJWKError", "jwk must not be nil")
	}
	if jwk.Kty != "" && jwk.Kty != "EC" {
		return nil, NewError("InvalidJWKError", "invalid jwk kty for ec key: "+jwk.Kty)
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, NewError("InvalidJWKError", "unsupported ec curve: "+jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, NewError("InvalidJWKError", fmt.Sprintf("invalid x in jwk: %s", err))
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, NewError("InvalidJWKError", fmt.Sprintf("invalid y in jwk: %s", err))
	}

	coordSize := curveCoordByteSize(curve)
	if len(xBytes) != coordSize || len(yBytes) != coordSize {
		return nil, NewError("InvalidJWKError", fmt.Sprintf("invalid ec coordinate length: got (%d, %d), expected %d", len(xBytes), len(yBytes), coordSize))
	}

	const uncompressedPointPrefix = 0x04
	uncompressed := make([]byte, 1+2*coordSize)
	uncompressed[0] = uncompressedPointPrefix
	copy(uncompressed[1:], xBytes)
	copy(uncompressed[1+coordSize:], yBytes)

	pub, ecErr := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if ecErr != nil {
		return nil, NewError("InvalidJWKError", fmt.Sprintf("invalid ec public key: %s", ecErr))
	}
	return pub, nil
}

// ParseEd25519PublicKeyFromJWK builds an ed25519.PublicKey from an OKP JWK.
func ParseEd25519PublicKeyFromJWK(jwk *JWK) (ed25519.PublicKey, Error) {
	if jwk == nil {
		return nil, NewError("InvalidJWKError", "jwk must not be nil")
	}
	if jwk.Kty != "" && jwk.Kty != "OKP" {
		return nil, NewError("InvalidJWKError", "invalid jwk kty for okp key: "+jwk.Kty)
	}
	if jwk.Crv != tls.Ed25519.String() {
		return nil, NewError("InvalidJWKError", "unsupported okp curve: "+jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, NewError("InvalidJWKError", fmt.Sprintf("invalid x in jwk: %s", err))
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, NewError("InvalidJWKError", fmt.Sprintf("invalid ed25519 key length: got %d, expected %d", len(xBytes), ed25519.PublicKeySize))
	}

	return ed25519.PublicKey(xBytes), nil
}

// verifyJwtSignature verifies a JWS signature for all supported Go stdlib algorithms.
func verifyJwtSignature(alg string, pubKey any, signingInput, sigBytes []byte) Error {
	switch alg {
	case AlgRS256:
		return verifyRSAPKCS1v15(pubKey, crypto.SHA256, signingInput, sigBytes)
	case AlgRS384:
		return verifyRSAPKCS1v15(pubKey, crypto.SHA384, signingInput, sigBytes)
	case AlgRS512:
		return verifyRSAPKCS1v15(pubKey, crypto.SHA512, signingInput, sigBytes)
	case AlgPS256:
		return verifyRSAPSS(pubKey, crypto.SHA256, signingInput, sigBytes)
	case AlgPS384:
		return verifyRSAPSS(pubKey, crypto.SHA384, signingInput, sigBytes)
	case AlgPS512:
		return verifyRSAPSS(pubKey, crypto.SHA512, signingInput, sigBytes)
	case AlgES256:
		return verifyECDSA(pubKey, elliptic.P256(), crypto.SHA256, signingInput, sigBytes)
	case AlgES384:
		return verifyECDSA(pubKey, elliptic.P384(), crypto.SHA384, signingInput, sigBytes)
	case AlgES512:
		return verifyECDSA(pubKey, elliptic.P521(), crypto.SHA512, signingInput, sigBytes)
	case AlgEdDSA:
		return verifyEdDSA(pubKey, signingInput, sigBytes)
	case AlgHS256:
		return verifyHMAC(pubKey, sha256.New, signingInput, sigBytes)
	case AlgHS384:
		return verifyHMAC(pubKey, sha512.New384, signingInput, sigBytes)
	case AlgHS512:
		return verifyHMAC(pubKey, sha512.New, signingInput, sigBytes)
	default:
		return NewError("UnsupportedAlgorithmError", "unsupported algorithm: "+alg)
	}
}

// prepareRSAVerify validates the RSA public key and computes the signing input digest.
func prepareRSAVerify(pubKey any, hashAlg crypto.Hash, signingInput []byte) (*rsa.PublicKey, []byte, Error) {
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok || rsaPub == nil {
		return nil, nil, NewError("InvalidPublicKeyError", "public key is not *rsa.PublicKey")
	}
	return rsaPub, computeJwtDigest(hashAlg, signingInput), nil
}

// verifyRSAPKCS1v15 verifies an RSASSA-PKCS1-v1_5 signature.
func verifyRSAPKCS1v15(pubKey any, hashAlg crypto.Hash, signingInput, sigBytes []byte) Error {
	rsaPub, hashed, err := prepareRSAVerify(pubKey, hashAlg, signingInput)
	if err != nil {
		return err
	}
	if verifyErr := rsa.VerifyPKCS1v15(rsaPub, hashAlg, hashed, sigBytes); verifyErr != nil {
		return NewError("SignatureVerificationError", fmt.Sprintf("jwt signature verification failed: %s", verifyErr))
	}
	return nil
}

// verifyRSAPSS verifies an RSASSA-PSS signature using RFC 7518 salt length matching the hash output size.
func verifyRSAPSS(pubKey any, hashAlg crypto.Hash, signingInput, sigBytes []byte) Error {
	rsaPub, hashed, err := prepareRSAVerify(pubKey, hashAlg, signingInput)
	if err != nil {
		return err
	}
	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	if verifyErr := rsa.VerifyPSS(rsaPub, hashAlg, hashed, sigBytes, opts); verifyErr != nil {
		return NewError("SignatureVerificationError", fmt.Sprintf("jwt signature verification failed: %s", verifyErr))
	}
	return nil
}

// verifyECDSA verifies a JWS ECDSA raw R||S signature against the expected elliptic curve.
func verifyECDSA(pubKey any, expectedCurve elliptic.Curve, hashAlg crypto.Hash, signingInput, sigBytes []byte) Error {
	ecPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok || ecPub == nil {
		return NewError("InvalidPublicKeyError", "public key is not *ecdsa.PublicKey")
	}
	if ecPub.Curve != expectedCurve {
		return NewError("InvalidPublicKeyError", "ecdsa public key curve mismatch")
	}

	coordSize := curveCoordByteSize(expectedCurve)
	if len(sigBytes) != 2*coordSize {
		return NewError("SignatureVerificationError", "invalid ecdsa signature length")
	}

	hashed := computeJwtDigest(hashAlg, signingInput)

	r := new(big.Int).SetBytes(sigBytes[:coordSize])
	s := new(big.Int).SetBytes(sigBytes[coordSize:])
	if !ecdsa.Verify(ecPub, hashed, r, s) {
		return NewError("SignatureVerificationError", "jwt ecdsa signature verification failed")
	}
	return nil
}

// verifyEdDSA verifies an Ed25519 signature over the raw JWS signing input.
func verifyEdDSA(pubKey any, signingInput, sigBytes []byte) Error {
	edPub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return NewError("InvalidPublicKeyError", "public key is not ed25519.PublicKey")
	}
	if len(edPub) != ed25519.PublicKeySize {
		return NewError("InvalidPublicKeyError", "invalid ed25519 public key length")
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return NewError("SignatureVerificationError", "invalid ed25519 signature length")
	}
	if !ed25519.Verify(edPub, signingInput, sigBytes) {
		return NewError("SignatureVerificationError", "jwt eddsa signature verification failed")
	}
	return nil
}

// verifyHMAC verifies a constant-time HMAC signature.
func verifyHMAC(pubKey any, hashFn func() hash.Hash, signingInput, sigBytes []byte) Error {
	secret, ok := pubKey.([]byte)
	if !ok {
		return NewError("InvalidSecretKeyError", "secret key is not []byte")
	}
	mac := hmac.New(hashFn, secret)
	Try(func() {
		_, writeErr := mac.Write(signingInput)
		RaiseNilErr(writeErr)
	}).LogError()
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(sigBytes, expectedSig) {
		return NewError("SignatureVerificationError", "jwt hmac signature mismatch")
	}
	return nil
}

// computeJwtDigest hashes data using the provided crypto.Hash algorithm.
func computeJwtDigest(h crypto.Hash, data []byte) []byte {
	hasher := h.New()
	Try(func() {
		_, writeErr := hasher.Write(data)
		RaiseNilErr(writeErr)
	}).LogError()
	return hasher.Sum(nil)
}

// curveCoordByteSize returns the fixed big-endian coordinate byte length for an elliptic curve.
func curveCoordByteSize(curve elliptic.Curve) int {
	const bitsPerByte = 8
	return (curve.Params().BitSize + bitsPerByte - 1) / bitsPerByte
}

// parseJwtTimestamp parses a numeric Unix timestamp from claim value.
func parseJwtTimestamp(val any) (int64, bool) {
	switch v := val.(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return n, true
		}
	default:
	}
	return 0, false
}
