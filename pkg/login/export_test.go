package login

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

func (this *OAuth2LoginAuthenticationProvider) SetInjectedUserServiceForTest(svc OAuth2UserService) {
	this.injectedUserService = OptionalOf(svc)
}

func (this *OAuth2LoginAuthenticationProvider) SetInjectedOidcUserServiceForTest(svc OidcUserService) {
	this.injectedOidcUserService = OptionalOf(svc)
}

func (this *OAuth2LoginAuthenticationProvider) GetUserServiceForTest() OAuth2UserService {
	return this.userService
}

func (this *OAuth2LoginAuthenticationProvider) GetOidcUserServiceForTest() OidcUserService {
	return this.oidcUserService
}

func (this *OAuth2LoginAuthenticationProvider) GetOrCreateDecoderForTest(reg *ClientRegistration) JwtDecoder {
	return this.getOrCreateDecoder(reg)
}

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
