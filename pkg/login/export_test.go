package login

import (
	"net/http"

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

// SetInjectedJwtDecoderForTest injects a mock or custom JwtDecoder for testing.
func (this *OAuth2LoginAuthenticationProvider) SetInjectedJwtDecoderForTest(dec JwtDecoder) {
	this.injectedJwtDecoder = OptionalOf(dec)
}

// SetHttpClientForTest injects an HTTP client for testing.
func (this *OAuth2LoginAuthenticationProvider) SetHttpClientForTest(client *http.Client) {
	this.httpClient = client
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

// IsValidHostForTest exposes isValidHost for testing.
func IsValidHostForTest(h string) bool {
	return isValidHost(h)
}

// ResolveForwardedHeadersForTest exposes resolveForwardedHeaders for testing.
func ResolveForwardedHeadersForTest(handler SecurityHandler, defaultScheme, defaultHost string) (scheme, host string) {
	return resolveForwardedHeaders(handler, defaultScheme, defaultHost)
}
