package config

import (
	"net/http"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/login"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/resourceserver"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/server"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
)

// OAuth2LoginConfigurer configures OAuth2 Login in HttpSecurityBuilder
type OAuth2LoginConfigurer struct {
	clientRegistrationRepo ClientRegistrationRepository
	authRequestRepo        AuthorizationRequestRepository
	authManager            AuthenticationManager
	contextHolder          SecurityContextHolder
	builder                *HttpSecurityBuilder
	defaultSuccessURL      string
	defaultRegistrationID  string
	loginProcessingURL     string
	authorizationBaseURI   string
}

func (this OAuth2LoginConfigurer) New(builder *HttpSecurityBuilder) *OAuth2LoginConfigurer {
	this.builder = builder
	this.defaultSuccessURL = "/"
	return &this
}

func NewOAuth2LoginConfigurer(builder *HttpSecurityBuilder) *OAuth2LoginConfigurer {
	return OAuth2LoginConfigurer{}.New(builder)
}

func (this *OAuth2LoginConfigurer) ClientRegistrationRepository(repo ClientRegistrationRepository) *OAuth2LoginConfigurer {
	this.clientRegistrationRepo = repo
	return this
}

func (this *OAuth2LoginConfigurer) AuthorizationRequestRepository(repo AuthorizationRequestRepository) *OAuth2LoginConfigurer {
	this.authRequestRepo = repo
	return this
}

func (this *OAuth2LoginConfigurer) AuthenticationManager(mgr AuthenticationManager) *OAuth2LoginConfigurer {
	this.authManager = mgr
	return this
}

func (this *OAuth2LoginConfigurer) SecurityContextHolder(holder SecurityContextHolder) *OAuth2LoginConfigurer {
	this.contextHolder = holder
	return this
}

func (this *OAuth2LoginConfigurer) DefaultSuccessURL(url string) *OAuth2LoginConfigurer {
	this.defaultSuccessURL = url
	return this
}

func (this *OAuth2LoginConfigurer) DefaultRegistrationID(id string) *OAuth2LoginConfigurer {
	this.defaultRegistrationID = id
	return this
}

func (this *OAuth2LoginConfigurer) LoginProcessingURL(url string) *OAuth2LoginConfigurer {
	this.loginProcessingURL = url
	return this
}

func (this *OAuth2LoginConfigurer) AuthorizationBaseURI(uri string) *OAuth2LoginConfigurer {
	this.authorizationBaseURI = uri
	return this
}

func (this *OAuth2LoginConfigurer) And() *HttpSecurityBuilder {
	cfg := &OAuth2LoginConfig{
		ClientRegistrationRepository: this.clientRegistrationRepo,
		AuthRequestRepository:        this.authRequestRepo,
		AuthenticationManager:        this.authManager,
		SecurityContextHolder:        this.contextHolder,
		DefaultRegistrationID:        this.defaultRegistrationID,
		DefaultSuccessURL:            this.defaultSuccessURL,
		LoginProcessingURL:           this.loginProcessingURL,
		AuthorizationBaseURI:         this.authorizationBaseURI,
	}
	this.builder.AddCustomSecurityFilter("oAuth2LoginAuthenticationFilter", cfg)
	return this.builder
}

// OAuth2ResourceServerConfigurer configures Bearer token authentication
type OAuth2ResourceServerConfigurer struct {
	builder       *HttpSecurityBuilder
	tokenResolver BearerTokenResolver
	authManager   AuthenticationManager
	contextHolder SecurityContextHolder
	jwtDecoder    JwtDecoder
	realmName     string
}

func (this OAuth2ResourceServerConfigurer) New(builder *HttpSecurityBuilder) *OAuth2ResourceServerConfigurer {
	this.builder = builder
	this.realmName = "rays-web-security-oauth2"
	return &this
}

func NewOAuth2ResourceServerConfigurer(builder *HttpSecurityBuilder) *OAuth2ResourceServerConfigurer {
	return OAuth2ResourceServerConfigurer{}.New(builder)
}

func (this *OAuth2ResourceServerConfigurer) TokenResolver(resolver BearerTokenResolver) *OAuth2ResourceServerConfigurer {
	this.tokenResolver = resolver
	return this
}

func (this *OAuth2ResourceServerConfigurer) AuthenticationManager(mgr AuthenticationManager) *OAuth2ResourceServerConfigurer {
	this.authManager = mgr
	return this
}

func (this *OAuth2ResourceServerConfigurer) SecurityContextHolder(holder SecurityContextHolder) *OAuth2ResourceServerConfigurer {
	this.contextHolder = holder
	return this
}

func (this *OAuth2ResourceServerConfigurer) JwtDecoder(decoder JwtDecoder) *OAuth2ResourceServerConfigurer {
	this.jwtDecoder = decoder
	return this
}

func (this *OAuth2ResourceServerConfigurer) Realm(realm string) *OAuth2ResourceServerConfigurer {
	this.realmName = realm
	return this
}

func (this *OAuth2ResourceServerConfigurer) And() *HttpSecurityBuilder {
	cfg := &BearerTokenConfig{
		TokenResolver:         this.tokenResolver,
		AuthenticationManager: this.authManager,
		SecurityContextHolder: this.contextHolder,
		JwtDecoder:            this.jwtDecoder,
		RealmName:             this.realmName,
	}
	this.builder.AddCustomSecurityFilter("bearerTokenAuthenticationFilter", cfg)
	return this.builder
}

// OAuth2AuthorizationServerConfigurer configures an OAuth2 Authorization Server
type OAuth2AuthorizationServerConfigurer struct {
	builder              *HttpSecurityBuilder
	settings             *AuthorizationServerSettings
	clientRepo           RegisteredClientRepository
	authorizationService OAuth2AuthorizationService
	tokenGenerator       OAuth2TokenGenerator
	jwkSource            JWKSource
	contextHolder        SecurityContextHolder
}

func (this OAuth2AuthorizationServerConfigurer) New(builder *HttpSecurityBuilder) *OAuth2AuthorizationServerConfigurer {
	this.builder = builder
	return &this
}

func NewOAuth2AuthorizationServerConfigurer(builder *HttpSecurityBuilder) *OAuth2AuthorizationServerConfigurer {
	return OAuth2AuthorizationServerConfigurer{}.New(builder)
}

func (this *OAuth2AuthorizationServerConfigurer) Settings(settings *AuthorizationServerSettings) *OAuth2AuthorizationServerConfigurer {
	this.settings = settings
	return this
}

func (this *OAuth2AuthorizationServerConfigurer) RegisteredClientRepository(repo RegisteredClientRepository) *OAuth2AuthorizationServerConfigurer {
	this.clientRepo = repo
	return this
}

func (this *OAuth2AuthorizationServerConfigurer) AuthorizationService(svc OAuth2AuthorizationService) *OAuth2AuthorizationServerConfigurer {
	this.authorizationService = svc
	return this
}

func (this *OAuth2AuthorizationServerConfigurer) TokenGenerator(gen OAuth2TokenGenerator) *OAuth2AuthorizationServerConfigurer {
	this.tokenGenerator = gen
	return this
}

func (this *OAuth2AuthorizationServerConfigurer) JWKSource(source JWKSource) *OAuth2AuthorizationServerConfigurer {
	this.jwkSource = source
	return this
}

func (this *OAuth2AuthorizationServerConfigurer) SecurityContextHolder(holder SecurityContextHolder) *OAuth2AuthorizationServerConfigurer {
	this.contextHolder = holder
	return this
}

func (this *OAuth2AuthorizationServerConfigurer) And() *HttpSecurityBuilder {
	cfg := &OAuth2AuthorizationServerConfig{
		Settings:              this.settings,
		ClientRepository:      this.clientRepo,
		AuthorizationService:  this.authorizationService,
		TokenGenerator:        this.tokenGenerator,
		JWKSource:             this.jwkSource,
		SecurityContextHolder: this.contextHolder,
	}

	this.builder.AddCustomSecurityFilter("oAuth2AuthorizationServerFilter", cfg)
	return this.builder
}

// Helper functions to initiate configurers cleanly on an HttpSecurityBuilder

var _ HttpSecurityBuilderOption = &OAuth2LoginConfigurer{}

func OAuth2Login(builder *HttpSecurityBuilder) *OAuth2LoginConfigurer {
	return OAuth2LoginConfigurer{}.New(builder)
}

var _ HttpSecurityBuilderOption = &OAuth2ResourceServerConfigurer{}

func OAuth2ResourceServer(builder *HttpSecurityBuilder) *OAuth2ResourceServerConfigurer {
	return OAuth2ResourceServerConfigurer{}.New(builder)
}

var _ HttpSecurityBuilderOption = &OAuth2AuthorizationServerConfigurer{}

func OAuth2AuthorizationServer(builder *HttpSecurityBuilder) *OAuth2AuthorizationServerConfigurer {
	return OAuth2AuthorizationServerConfigurer{}.New(builder)
}

// Ensure unused import doesn't cause compiler error
var _ = http.StatusOK
