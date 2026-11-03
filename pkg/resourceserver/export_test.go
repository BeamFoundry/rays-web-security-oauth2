package resourceserver

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

func (this *JwtAuthenticationProvider) SetInjectedDecoderForTest(dec JwtDecoder) {
	this.injectedDecoder = OptionalOf(dec)
}

func (this *JwtAuthenticationProvider) SetInjectedConverterForTest(conv JwtAuthenticationConverter) {
	this.injectedConverter = OptionalOf(conv)
}

func (this *JwtAuthenticationProvider) GetDecoderForTest() JwtDecoder {
	return this.jwtDecoder
}

func (this *JwtAuthenticationProvider) GetConverterForTest() JwtAuthenticationConverter {
	return this.converter
}

func (this *BearerTokenAuthenticationFilter) SetInjectedDepsForTest(
	resolver BearerTokenResolver,
	mgr AuthenticationManager,
	holder SecurityContextHolder,
) {
	if resolver != nil {
		this.injectedTokenResolver = OptionalOf(resolver)
	}
	if mgr != nil {
		this.injectedAuthManager = OptionalOf(mgr)
	}
	if holder != nil {
		this.injectedContextHolder = OptionalOf(holder)
	}
}

func (this *BearerTokenAuthenticationFilter) GetDepsForTest() (BearerTokenResolver, AuthenticationManager, SecurityContextHolder) {
	return this.tokenResolver, this.authenticationManager, this.securityContextHolder
}

func (this *OpaqueTokenAuthenticationProvider) SetInjectedIntrospectorForTest(intro OpaqueTokenIntrospector) {
	this.injectedIntrospector = OptionalOf(intro)
}

func (this *OpaqueTokenAuthenticationProvider) SetInjectedConverterForTest(conv OpaqueTokenAuthenticationConverter) {
	this.injectedConverter = OptionalOf(conv)
}

func (this *OpaqueTokenAuthenticationProvider) GetIntrospectorForTest() OpaqueTokenIntrospector {
	return this.introspector
}

func (this *OpaqueTokenAuthenticationProvider) GetConverterForTest() OpaqueTokenAuthenticationConverter {
	return this.converter
}

func (this *BearerTokenAuthenticationFilter) SetInjectedIntrospectorForTest(intro OpaqueTokenIntrospector) {
	this.injectedIntrospector = OptionalOf(intro)
}

func (this *BearerTokenAuthenticationFilter) SetInjectedOpaqueConverterForTest(conv OpaqueTokenAuthenticationConverter) {
	this.injectedOpaqueConverter = OptionalOf(conv)
}
