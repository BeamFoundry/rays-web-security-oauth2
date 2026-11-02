package server

import (
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

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

type ServerFilterDeps struct {
	ClientRepo     RegisteredClientRepository
	ContextHolder  SecurityContextHolder
	JWKSource      JWKSource
	TokenGenerator OAuth2TokenGenerator
	AuthService    OAuth2AuthorizationService
	Settings       *AuthorizationServerSettings
}

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
