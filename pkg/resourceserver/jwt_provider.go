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

func (this JwtAuthenticationProvider) New(decoder JwtDecoder) *JwtAuthenticationProvider {
	this.jwtDecoder = decoder
	this.converter = DefaultJwtAuthenticationConverter{}.New()
	return &this
}

func NewJwtAuthenticationProvider(decoder JwtDecoder) *JwtAuthenticationProvider {
	return JwtAuthenticationProvider{}.New(decoder)
}

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

func (this *JwtAuthenticationProvider) WithConverter(c JwtAuthenticationConverter) *JwtAuthenticationProvider {
	this.converter = c
	return this
}

func (this *JwtAuthenticationProvider) Supports(auth Authentication) bool {
	_, ok := auth.(*BearerTokenAuthenticationToken)
	return ok
}

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
