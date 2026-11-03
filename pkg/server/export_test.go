package server

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// SetInjectedDepsForTest injects dependencies into OAuth2AuthorizationServerFilter for testing.
func (this *OAuth2AuthorizationServerFilter) SetInjectedDepsForTest(
	clientRepo RegisteredClientRepository,
	holder SecurityContextHolder,
	jwkSource JWKSource,
	tokenGen OAuth2TokenGenerator,
	authService OAuth2AuthorizationService,
	settings *AuthorizationServerSettings,
) {
	if clientRepo != nil {
		this.injectedClientRepo = OptionalOf(clientRepo)
	}
	if holder != nil {
		this.injectedContextHolder = OptionalOf(holder)
	}
	if jwkSource != nil {
		this.injectedJWKSource = OptionalOf(jwkSource)
	}
	if tokenGen != nil {
		this.injectedTokenGenerator = OptionalOf(tokenGen)
	}
	if authService != nil {
		this.injectedAuthService = OptionalOf(authService)
	}
	if settings != nil {
		this.injectedSettings = OptionalOf(settings)
	}
}

// ServerFilterDeps holds the internal dependencies of OAuth2AuthorizationServerFilter for test inspection.
type ServerFilterDeps struct {
	ClientRepo     RegisteredClientRepository
	ContextHolder  SecurityContextHolder
	JWKSource      JWKSource
	TokenGenerator OAuth2TokenGenerator
	AuthService    OAuth2AuthorizationService
	Settings       *AuthorizationServerSettings
}

// GetDepsForTest returns the configured internal dependencies of OAuth2AuthorizationServerFilter for test assertions.
func (this *OAuth2AuthorizationServerFilter) GetDepsForTest() *ServerFilterDeps {
	return &ServerFilterDeps{
		ClientRepo:     this.clientRepo,
		ContextHolder:  this.securityContextHolder,
		JWKSource:      this.jwkSource,
		TokenGenerator: this.tokenGenerator,
		AuthService:    this.authorizationService,
		Settings:       this.settings,
	}
}

// UntrackForTest removes the tracked ID from InMemoryOAuth2AuthorizationService for unit testing fallback removal branches.
func (this *InMemoryOAuth2AuthorizationService) UntrackForTest(id string) {
	this.mu.Lock()
	defer this.mu.Unlock()
	delete(this.tracked, id)
}

// SetAuthCodeForTest sets an authorization directly into byAuthCode for unit testing edge cases.
func (this *InMemoryOAuth2AuthorizationService) SetAuthCodeForTest(code string, auth *OAuth2Authorization) {
	this.mu.Lock()
	defer this.mu.Unlock()
	this.byAuthCode[code] = auth
}
