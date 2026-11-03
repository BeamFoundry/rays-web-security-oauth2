package login

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// SetInjectedUserServiceForTest injects a mock or custom OAuth2UserService for testing.
func (this *OAuth2LoginAuthenticationProvider) SetInjectedUserServiceForTest(svc OAuth2UserService) {
	this.injectedUserService = OptionalOf(svc)
}

// SetInjectedOidcUserServiceForTest injects a mock or custom OidcUserService for testing.
func (this *OAuth2LoginAuthenticationProvider) SetInjectedOidcUserServiceForTest(svc OidcUserService) {
	this.injectedOidcUserService = OptionalOf(svc)
}

// GetUserServiceForTest returns the configured OAuth2UserService for test assertions.
func (this *OAuth2LoginAuthenticationProvider) GetUserServiceForTest() OAuth2UserService {
	return this.userService
}

// GetOidcUserServiceForTest returns the configured OidcUserService for test assertions.
func (this *OAuth2LoginAuthenticationProvider) GetOidcUserServiceForTest() OidcUserService {
	return this.oidcUserService
}

// GetOrCreateDecoderForTest exposes getOrCreateDecoder for testing JWKS decoder caching and initialization.
func (this *OAuth2LoginAuthenticationProvider) GetOrCreateDecoderForTest(reg *ClientRegistration) JwtDecoder {
	return this.getOrCreateDecoder(reg)
}

// SetInjectedDepsForTest injects filter dependencies into OAuth2LoginAuthenticationFilter for testing.
func (this *OAuth2LoginAuthenticationFilter) SetInjectedDepsForTest(
	clientRepo ClientRegistrationRepository,
	authReqRepo AuthorizationRequestRepository,
	authMgr AuthenticationManager,
	ctxHolder SecurityContextHolder,
) {
	if clientRepo != nil {
		this.injectedClientRepo = OptionalOf(clientRepo)
	}
	if authReqRepo != nil {
		this.injectedAuthReqRepo = OptionalOf(authReqRepo)
	}
	if authMgr != nil {
		this.injectedAuthManager = OptionalOf(authMgr)
	}
	if ctxHolder != nil {
		this.injectedContextHolder = OptionalOf(ctxHolder)
	}
}
