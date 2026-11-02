package jwt

import (
	"context"
	"fmt"
	"maps"
	"time"

	. "github.com/BeamFoundry/rays/pkg/lang"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// JwxJwtDecoder implements JwtDecoder using github.com/lestrrat-go/jwx/v3
// Supporting RS256-512, PS256-512, ES256-512, EdDSA, HS256-512, and remote JWKS
type JwxJwtDecoder struct {
	keySet    jwk.Set
	jwksURI   string
	issuer    string
	audience  string
	clockSkew time.Duration
}

// NewWithKeySet creates a decoder verifying tokens against a local or static JWK Set
func (this JwxJwtDecoder) NewWithKeySet(set jwk.Set) *JwxJwtDecoder {
	this.keySet = set
	this.clockSkew = 60 * time.Second
	return &this
}

// NewWithRemoteJWKS creates a decoder that fetches keys from a remote jwks_uri
func (this JwxJwtDecoder) NewWithRemoteJWKS(jwksURI string) *JwxJwtDecoder {
	this.jwksURI = jwksURI
	this.clockSkew = 60 * time.Second
	return &this
}

func NewJwxJwtDecoderWithKeySet(set jwk.Set) *JwxJwtDecoder {
	return JwxJwtDecoder{}.NewWithKeySet(set)
}

func NewJwxJwtDecoderWithRemoteJWKS(jwksURI string) *JwxJwtDecoder {
	return JwxJwtDecoder{}.NewWithRemoteJWKS(jwksURI)
}

func (this *JwxJwtDecoder) WithIssuer(issuer string) *JwxJwtDecoder {
	this.issuer = issuer
	return this
}

func (this *JwxJwtDecoder) WithAudience(aud string) *JwxJwtDecoder {
	this.audience = aud
	return this
}

func (this *JwxJwtDecoder) WithClockSkew(skew time.Duration) *JwxJwtDecoder {
	this.clockSkew = skew
	return this
}

// Decode parses, verifies the signature, and validates standard claims
func (this *JwxJwtDecoder) Decode(tokenString string) (*Jwt, Error) {
	ctx := context.Background()

	var parseOptions []jwt.ParseOption
	parseOptions = append(parseOptions, jwt.WithValidate(false))

	if this.jwksURI != "" {
		set, err := jwk.Fetch(ctx, this.jwksURI)
		if err != nil {
			return nil, NewError("JWKSFetchError", fmt.Sprintf("failed to fetch remote jwks: %s", err))
		}
		parseOptions = append(parseOptions, jwt.WithKeySet(set))
	} else if this.keySet != nil {
		parseOptions = append(parseOptions, jwt.WithKeySet(this.keySet))
	}

	tok, err := jwt.Parse([]byte(tokenString), parseOptions...)
	if err != nil {
		return nil, NewError("JwtParseError", fmt.Sprintf("failed to parse or verify jwt: %s", err))
	}

	// Validate standard claims
	var validateOptions []jwt.ValidateOption
	if this.clockSkew > 0 {
		validateOptions = append(validateOptions, jwt.WithAcceptableSkew(this.clockSkew))
	}
	if this.issuer != "" {
		validateOptions = append(validateOptions, jwt.WithIssuer(this.issuer))
	}
	if this.audience != "" {
		validateOptions = append(validateOptions, jwt.WithAudience(this.audience))
	}

	if valErr := jwt.Validate(tok, validateOptions...); valErr != nil {
		return nil, NewError("JwtValidationError", fmt.Sprintf("jwt validation failed: %s", valErr))
	}

	// Convert claims to standard map[string]any
	claimsMap := make(map[string]any)
	for _, key := range tok.Keys() {
		var val any
		if getErr := tok.Get(key, &val); getErr == nil {
			claimsMap[key] = val
		} else {
			NewErrorFrom(getErr).LogError()
		}
	}

	headersMap, _, unverifiedErr := ParseUnverified(tokenString)
	if unverifiedErr != nil || headersMap == nil {
		headersMap = make(map[string]any)
	}

	var issuedAt, expiresAt time.Time
	if iat, ok := tok.IssuedAt(); ok {
		issuedAt = iat
	}
	if exp, ok := tok.Expiration(); ok {
		expiresAt = exp
	}

	return NewJwt(tokenString, issuedAt, expiresAt, headersMap, claimsMap), nil
}

// JwxJwtEncoder signs JWT tokens using github.com/lestrrat-go/jwx/v3
type JwxJwtEncoder struct {
	signKey   any
	keyID     string
	algorithm jwa.SignatureAlgorithm
}

// New creates an encoder supporting any RSA, ECDSA, Ed25519 or HMAC key
func (this JwxJwtEncoder) New(signKey any, alg jwa.SignatureAlgorithm, keyID string) *JwxJwtEncoder {
	this.signKey = signKey
	this.algorithm = alg
	this.keyID = keyID
	return &this
}

func NewJwxJwtEncoder(signKey any, alg jwa.SignatureAlgorithm, keyID string) *JwxJwtEncoder {
	return JwxJwtEncoder{}.New(signKey, alg, keyID)
}

func (this *JwxJwtEncoder) Encode(params *JwtEncoderParameters) (*Jwt, Error) {
	builder := jwt.NewBuilder()

	if params.ClaimsSet != nil {
		cs := params.ClaimsSet
		if cs.Issuer != "" {
			builder.Issuer(cs.Issuer)
		}
		if cs.Subject != "" {
			builder.Subject(cs.Subject)
		}
		if len(cs.Audience) > 0 {
			builder.Audience(cs.Audience)
		}
		if !cs.ExpiresAt.IsZero() {
			builder.Expiration(cs.ExpiresAt)
		}
		if !cs.NotBefore.IsZero() {
			builder.NotBefore(cs.NotBefore)
		}
		if !cs.IssuedAt.IsZero() {
			builder.IssuedAt(cs.IssuedAt)
		}
		if cs.JWTID != "" {
			builder.JwtID(cs.JWTID)
		}
		for k, v := range cs.Claims {
			builder.Claim(k, v)
		}
	}

	tok, err := builder.Build()
	if err != nil {
		return nil, NewError("JwtBuildError", fmt.Sprintf("failed to build token: %s", err))
	}

	// Sign key setup
	key, err := jwk.Import(this.signKey)
	if err != nil {
		return nil, NewError("JWKImportError", fmt.Sprintf("failed to import jwk from raw key: %s", err))
	}
	if this.keyID != "" {
		if setErr := key.Set(jwk.KeyIDKey, this.keyID); setErr != nil {
			NewErrorFrom(setErr).LogError()
		}
	}
	if setErr := key.Set(jwk.AlgorithmKey, this.algorithm); setErr != nil {
		NewErrorFrom(setErr).LogError()
	}

	signedBytes, err := jwt.Sign(tok, jwt.WithKey(this.algorithm, key))
	if err != nil {
		return nil, NewError("JwtSignError", fmt.Sprintf("failed to sign token: %s", err))
	}

	var issuedAt, expiresAt time.Time
	if params.ClaimsSet != nil {
		issuedAt = params.ClaimsSet.IssuedAt
		expiresAt = params.ClaimsSet.ExpiresAt
	}

	headers := map[string]any{
		"alg": this.algorithm.String(),
		"typ": "JWT",
	}
	if this.keyID != "" {
		headers["kid"] = this.keyID
	}

	claims := make(map[string]any)
	if params.ClaimsSet != nil {
		maps.Copy(claims, params.ClaimsSet.Claims)
		if params.ClaimsSet.Subject != "" {
			claims["sub"] = params.ClaimsSet.Subject
		}
		if params.ClaimsSet.Issuer != "" {
			claims["iss"] = params.ClaimsSet.Issuer
		}
	}

	return NewJwt(string(signedBytes), issuedAt, expiresAt, headers, claims), nil
}
