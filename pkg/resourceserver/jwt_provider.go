package resourceserver

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// JwtAuthenticationProvider validates bearer token strings against a JwtDecoder
type JwtAuthenticationProvider struct {
	Component
	jwtDecoder        JwtDecoder
	converter         JwtAuthenticationConverter
	injectedDecoder   Optional[JwtDecoder]                 `@:"Inject"`
	injectedConverter Optional[JwtAuthenticationConverter] `@:"Inject"`
}

var (
	_, _                        = any(&JwtAuthenticationProvider{}).(Stereotype)
	_    AuthenticationProvider = &JwtAuthenticationProvider{}
	_    BeamPostConstruct      = &JwtAuthenticationProvider{}
	_    Error
)

// New creates a new JwtAuthenticationProvider with the given JwtDecoder and a DefaultJwtAuthenticationConverter.
func (this JwtAuthenticationProvider) New(decoder JwtDecoder) *JwtAuthenticationProvider {
	this.jwtDecoder = decoder
	this.converter = DefaultJwtAuthenticationConverter{}.New()
	return &this
}

// NewJwtAuthenticationProvider creates a new JwtAuthenticationProvider.
func NewJwtAuthenticationProvider(decoder JwtDecoder) *JwtAuthenticationProvider {
	return JwtAuthenticationProvider{}.New(decoder)
}

// PostConstruct initializes injected JwtDecoder and JwtAuthenticationConverter dependencies.
func (this *JwtAuthenticationProvider) PostConstruct() Error {
	if dec, ok := this.injectedDecoder.Get(); ok {
		this.jwtDecoder = dec
	}
	if conv, ok := this.injectedConverter.Get(); ok {
		this.converter = conv
	} else if this.converter == nil {
		this.converter = DefaultJwtAuthenticationConverter{}.New()
	}
	return nil
}

// WithConverter sets the JwtAuthenticationConverter used to convert decoded JWTs into Authentication tokens.
func (this *JwtAuthenticationProvider) WithConverter(c JwtAuthenticationConverter) *JwtAuthenticationProvider {
	this.converter = c
	return this
}

// WithDecoder sets the JwtDecoder used to verify and decode bearer token strings.
func (this *JwtAuthenticationProvider) WithDecoder(decoder JwtDecoder) *JwtAuthenticationProvider {
	this.jwtDecoder = decoder
	return this
}

// Supports reports whether the given Authentication is a BearerTokenAuthenticationToken.
func (this *JwtAuthenticationProvider) Supports(auth Authentication) bool {
	_, ok := auth.(*BearerTokenAuthenticationToken)
	return ok
}

// Authenticate decodes and verifies the bearer token as a JWT and converts it into an authenticated JwtAuthenticationToken.
func (this *JwtAuthenticationProvider) Authenticate(auth Authentication) (Authentication, AuthenticationException) {
	bearerToken, ok := auth.(*BearerTokenAuthenticationToken)
	if !ok {
		return auth, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorInvalidRequest, ErrorDescription: "token is not BearerTokenAuthenticationToken"},
			auth,
		)
	}

	decoder := this.jwtDecoder
	if decoder == nil {
		if dec, ok := this.injectedDecoder.Get(); ok {
			decoder = dec
			this.jwtDecoder = dec
		}
	}
	if decoder == nil {
		return auth, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorServerError, ErrorDescription: "jwtDecoder not configured"},
			auth,
		)
	}

	decodedJwt, err := decoder.Decode(bearerToken.Token)
	if err != nil {
		err.LogError()
		return auth, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorInvalidToken, ErrorDescription: "invalid token: " + err.Error()},
			auth,
		)
	}

	conv := this.converter
	if conv == nil {
		if c, ok := this.injectedConverter.Get(); ok {
			conv = c
		} else {
			conv = DefaultJwtAuthenticationConverter{}.New()
		}
		this.converter = conv
	}

	authenticatedToken, err := conv.Convert(decodedJwt)
	if err != nil {
		err.LogError()
		return auth, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorInvalidToken, ErrorDescription: "claims conversion failed: " + err.Error()},
			auth,
		)
	}

	return authenticatedToken, nil
}
