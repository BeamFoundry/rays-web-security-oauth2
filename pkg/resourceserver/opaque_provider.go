package resourceserver

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OpaqueTokenAuthenticationProvider validates bearer token strings against an OpaqueTokenIntrospector
type OpaqueTokenAuthenticationProvider struct {
	Component
	introspector         OpaqueTokenIntrospector
	converter            OpaqueTokenAuthenticationConverter
	injectedIntrospector Optional[OpaqueTokenIntrospector]            `@:"Inject"`
	injectedConverter    Optional[OpaqueTokenAuthenticationConverter] `@:"Inject"`
}

var (
	_, _                        = any(&OpaqueTokenAuthenticationProvider{}).(Stereotype)
	_    AuthenticationProvider = &OpaqueTokenAuthenticationProvider{}
	_    BeamPostConstruct      = &OpaqueTokenAuthenticationProvider{}
	_    Error
)

func (this OpaqueTokenAuthenticationProvider) New(introspector OpaqueTokenIntrospector) *OpaqueTokenAuthenticationProvider {
	this.introspector = introspector
	this.converter = DefaultOpaqueTokenAuthenticationConverter{}.New()
	return &this
}

func NewOpaqueTokenAuthenticationProvider(introspector OpaqueTokenIntrospector) *OpaqueTokenAuthenticationProvider {
	return OpaqueTokenAuthenticationProvider{}.New(introspector)
}

func (this *OpaqueTokenAuthenticationProvider) PostConstruct() Error {
	if intro, ok := this.injectedIntrospector.Get(); ok {
		this.introspector = intro
	}
	if conv, ok := this.injectedConverter.Get(); ok {
		this.converter = conv
	} else if this.converter == nil {
		this.converter = DefaultOpaqueTokenAuthenticationConverter{}.New()
	}
	return nil
}

func (this *OpaqueTokenAuthenticationProvider) WithConverter(c OpaqueTokenAuthenticationConverter) *OpaqueTokenAuthenticationProvider {
	this.converter = c
	return this
}

func (this *OpaqueTokenAuthenticationProvider) WithIntrospector(introspector OpaqueTokenIntrospector) *OpaqueTokenAuthenticationProvider {
	this.introspector = introspector
	return this
}

func (this *OpaqueTokenAuthenticationProvider) Supports(auth Authentication) bool {
	_, ok := auth.(*BearerTokenAuthenticationToken)
	return ok
}

func (this *OpaqueTokenAuthenticationProvider) Authenticate(auth Authentication) (Authentication, AuthenticationException) {
	bearerToken, ok := auth.(*BearerTokenAuthenticationToken)
	if !ok {
		return auth, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorInvalidRequest, ErrorDescription: "token is not BearerTokenAuthenticationToken"},
			auth,
		)
	}

	introspector := this.introspector
	if introspector == nil {
		if intro, ok := this.injectedIntrospector.Get(); ok {
			introspector = intro
			this.introspector = intro
		}
	}
	if introspector == nil {
		return auth, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorServerError, ErrorDescription: "opaqueTokenIntrospector not configured"},
			auth,
		)
	}

	principal, err := introspector.Introspect(bearerToken.Token)
	if err != nil {
		err.LogError()
		if authEx, ok := err.(AuthenticationException); ok {
			return auth, authEx
		}
		return auth, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorInvalidToken, ErrorDescription: "invalid token"},
			auth,
		)
	}

	conv := this.converter
	if conv == nil {
		if c, ok := this.injectedConverter.Get(); ok {
			conv = c
		} else {
			conv = DefaultOpaqueTokenAuthenticationConverter{}.New()
		}
		this.converter = conv
	}

	authenticatedToken, err := conv.Convert(bearerToken.Token, principal)
	if err != nil {
		err.LogError()
		return auth, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorInvalidToken, ErrorDescription: "claims conversion failed"},
			auth,
		)
	}

	return authenticatedToken, nil
}
