package resourceserver

import (
	"net/url"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// SetInjectedDecoderForTest injects a JwtDecoder into JwtAuthenticationProvider for testing.
func (this *JwtAuthenticationProvider) SetInjectedDecoderForTest(dec JwtDecoder) {
	this.injectedDecoder = OptionalOf(dec)
}

// SetInjectedConverterForTest injects a JwtAuthenticationConverter into JwtAuthenticationProvider for testing.
func (this *JwtAuthenticationProvider) SetInjectedConverterForTest(conv JwtAuthenticationConverter) {
	this.injectedConverter = OptionalOf(conv)
}

// GetDecoderForTest returns the configured JwtDecoder from JwtAuthenticationProvider for test assertions.
func (this *JwtAuthenticationProvider) GetDecoderForTest() JwtDecoder {
	return this.jwtDecoder
}

// GetConverterForTest returns the configured JwtAuthenticationConverter from JwtAuthenticationProvider for test assertions.
func (this *JwtAuthenticationProvider) GetConverterForTest() JwtAuthenticationConverter {
	return this.converter
}

// SetInjectedDepsForTest injects resolver, authentication manager, and security context holder dependencies into BearerTokenAuthenticationFilter for testing.
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

// GetDepsForTest returns the internal resolver, authentication manager, and security context holder of BearerTokenAuthenticationFilter for test assertions.
func (this *BearerTokenAuthenticationFilter) GetDepsForTest() (BearerTokenResolver, AuthenticationManager, SecurityContextHolder) {
	return this.tokenResolver, this.authenticationManager, this.securityContextHolder
}

// SetInjectedIntrospectorForTest injects an OpaqueTokenIntrospector into OpaqueTokenAuthenticationProvider for testing.
func (this *OpaqueTokenAuthenticationProvider) SetInjectedIntrospectorForTest(intro OpaqueTokenIntrospector) {
	this.injectedIntrospector = OptionalOf(intro)
}

// SetInjectedConverterForTest injects an OpaqueTokenAuthenticationConverter into OpaqueTokenAuthenticationProvider for testing.
func (this *OpaqueTokenAuthenticationProvider) SetInjectedConverterForTest(conv OpaqueTokenAuthenticationConverter) {
	this.injectedConverter = OptionalOf(conv)
}

// GetIntrospectorForTest returns the configured OpaqueTokenIntrospector from OpaqueTokenAuthenticationProvider for test assertions.
func (this *OpaqueTokenAuthenticationProvider) GetIntrospectorForTest() OpaqueTokenIntrospector {
	return this.introspector
}

// GetConverterForTest returns the configured OpaqueTokenAuthenticationConverter from OpaqueTokenAuthenticationProvider for test assertions.
func (this *OpaqueTokenAuthenticationProvider) GetConverterForTest() OpaqueTokenAuthenticationConverter {
	return this.converter
}

// SetInjectedIntrospectorForTest injects an OpaqueTokenIntrospector into BearerTokenAuthenticationFilter for testing.
func (this *BearerTokenAuthenticationFilter) SetInjectedIntrospectorForTest(intro OpaqueTokenIntrospector) {
	this.injectedIntrospector = OptionalOf(intro)
}

// SetInjectedOpaqueConverterForTest injects an OpaqueTokenAuthenticationConverter into BearerTokenAuthenticationFilter for testing.
func (this *BearerTokenAuthenticationFilter) SetInjectedOpaqueConverterForTest(conv OpaqueTokenAuthenticationConverter) {
	this.injectedOpaqueConverter = OptionalOf(conv)
}

// SetInjectedJwtDecoderForTest injects a JwtDecoder into BearerTokenAuthenticationFilter for testing.
func (this *BearerTokenAuthenticationFilter) SetInjectedJwtDecoderForTest(dec JwtDecoder) {
	this.injectedJwtDecoder = OptionalOf(dec)
}

// SetInjectedConverterForTest injects a JwtAuthenticationConverter into BearerTokenAuthenticationFilter for testing.
func (this *BearerTokenAuthenticationFilter) SetInjectedConverterForTest(conv JwtAuthenticationConverter) {
	this.injectedConverter = OptionalOf(conv)
}

// NewBearerAuthenticationManagerForTest constructs a bearerAuthenticationManager for testing provider delegation and fallback behavior.
func NewBearerAuthenticationManagerForTest(
	jwtProvider *JwtAuthenticationProvider,
	opaqueProvider *OpaqueTokenAuthenticationProvider,
	fallback AuthenticationManager,
) AuthenticationManager {
	return &bearerAuthenticationManager{
		jwtProvider:    jwtProvider,
		opaqueProvider: opaqueProvider,
		fallback:       fallback,
	}
}

// IsSameOriginForTest exposes isSameOrigin for unit testing redirect origin checks.
func IsSameOriginForTest(target, configured *url.URL) bool {
	return isSameOrigin(target, configured)
}

// EffectivePortForTest exposes effectivePort for unit testing URL port resolution.
func EffectivePortForTest(u *url.URL) string {
	return effectivePort(u)
}

// ParseIntegerTimestampForTest exposes parseIntegerTimestamp for unit testing timestamp claim parsing.
func ParseIntegerTimestampForTest(val any) (int64, bool) {
	return parseIntegerTimestamp(val)
}
