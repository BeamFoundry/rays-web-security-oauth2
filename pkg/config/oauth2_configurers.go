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
	baseURL                string
	trustedProxy           bool
}

// New creates a new OAuth2LoginConfigurer attached to the given HttpSecurityBuilder.
func (this OAuth2LoginConfigurer) New(builder *HttpSecurityBuilder) *OAuth2LoginConfigurer {
	this.builder = builder
	this.defaultSuccessURL = "/"
	return &this
}

// NewOAuth2LoginConfigurer creates a new OAuth2LoginConfigurer attached to the given HttpSecurityBuilder.
func NewOAuth2LoginConfigurer(builder *HttpSecurityBuilder) *OAuth2LoginConfigurer {
	return OAuth2LoginConfigurer{}.New(builder)
}

// ClientRegistrationRepository sets the repository used to resolve OAuth 2.0 client registrations.
func (this *OAuth2LoginConfigurer) ClientRegistrationRepository(repo ClientRegistrationRepository) *OAuth2LoginConfigurer {
	this.clientRegistrationRepo = repo
	return this
}

// AuthorizationRequestRepository sets the repository used to persist authorization requests across redirects.
func (this *OAuth2LoginConfigurer) AuthorizationRequestRepository(repo AuthorizationRequestRepository) *OAuth2LoginConfigurer {
	this.authRequestRepo = repo
	return this
}

// AuthenticationManager sets the AuthenticationManager used to authenticate authorization code callbacks.
func (this *OAuth2LoginConfigurer) AuthenticationManager(mgr AuthenticationManager) *OAuth2LoginConfigurer {
	this.authManager = mgr
	return this
}

// SecurityContextHolder sets the SecurityContextHolder used to store the authenticated user context.
func (this *OAuth2LoginConfigurer) SecurityContextHolder(holder SecurityContextHolder) *OAuth2LoginConfigurer {
	this.contextHolder = holder
	return this
}

// DefaultSuccessURL sets the fallback URL to redirect to after successful login.
func (this *OAuth2LoginConfigurer) DefaultSuccessURL(url string) *OAuth2LoginConfigurer {
	this.defaultSuccessURL = url
	return this
}

// DefaultRegistrationID sets the default client registration ID used when redirecting unauthenticated users.
func (this *OAuth2LoginConfigurer) DefaultRegistrationID(id string) *OAuth2LoginConfigurer {
	this.defaultRegistrationID = id
	return this
}

// LoginProcessingURL sets the base URI prefix that intercepts OAuth 2.0 authorization callbacks.
func (this *OAuth2LoginConfigurer) LoginProcessingURL(url string) *OAuth2LoginConfigurer {
	this.loginProcessingURL = url
	return this
}

// AuthorizationBaseURI sets the base URI prefix that initiates OAuth 2.0 authorization redirects.
func (this *OAuth2LoginConfigurer) AuthorizationBaseURI(uri string) *OAuth2LoginConfigurer {
	this.authorizationBaseURI = uri
	return this
}

// BaseURL sets the external base URL used to resolve relative callback redirect URIs.
func (this *OAuth2LoginConfigurer) BaseURL(url string) *OAuth2LoginConfigurer {
	this.baseURL = url
	return this
}

// TrustedProxy enables or disables trusting X-Forwarded-* headers when resolving callback redirect URIs.
func (this *OAuth2LoginConfigurer) TrustedProxy(trusted bool) *OAuth2LoginConfigurer {
	this.trustedProxy = trusted
	return this
}

// And registers the OAuth2LoginAuthenticationFilter configuration and returns the parent HttpSecurityBuilder.
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
		BaseURL:                      this.baseURL,
		TrustedProxy:                 this.trustedProxy,
	}
	this.builder.AddCustomSecurityFilter("oAuth2LoginAuthenticationFilter", cfg)
	return this.builder
}

// OAuth2ResourceServerConfigurer configures Bearer token authentication
type OAuth2ResourceServerConfigurer struct {
	builder                 *HttpSecurityBuilder
	tokenResolver           BearerTokenResolver
	authManager             AuthenticationManager
	contextHolder           SecurityContextHolder
	jwtDecoder              JwtDecoder
	opaqueTokenIntrospector OpaqueTokenIntrospector
	realmName               string
}

// New creates a new OAuth2ResourceServerConfigurer attached to the given HttpSecurityBuilder.
func (this OAuth2ResourceServerConfigurer) New(builder *HttpSecurityBuilder) *OAuth2ResourceServerConfigurer {
	this.builder = builder
	this.realmName = "rays-web-security-oauth2"
	return &this
}

// NewOAuth2ResourceServerConfigurer creates a new OAuth2ResourceServerConfigurer attached to the given HttpSecurityBuilder.
func NewOAuth2ResourceServerConfigurer(builder *HttpSecurityBuilder) *OAuth2ResourceServerConfigurer {
	return OAuth2ResourceServerConfigurer{}.New(builder)
}

// TokenResolver sets the BearerTokenResolver used to extract bearer tokens from incoming HTTP requests.
func (this *OAuth2ResourceServerConfigurer) TokenResolver(resolver BearerTokenResolver) *OAuth2ResourceServerConfigurer {
	this.tokenResolver = resolver
	return this
}

// AuthenticationManager sets the AuthenticationManager used to authenticate extracted bearer tokens.
func (this *OAuth2ResourceServerConfigurer) AuthenticationManager(mgr AuthenticationManager) *OAuth2ResourceServerConfigurer {
	this.authManager = mgr
	return this
}

// SecurityContextHolder sets the SecurityContextHolder used to store the authenticated bearer token principal.
func (this *OAuth2ResourceServerConfigurer) SecurityContextHolder(holder SecurityContextHolder) *OAuth2ResourceServerConfigurer {
	this.contextHolder = holder
	return this
}

// JwtDecoder configures a JwtDecoder for JWT-based bearer token authentication.
func (this *OAuth2ResourceServerConfigurer) JwtDecoder(decoder JwtDecoder) *OAuth2ResourceServerConfigurer {
	this.jwtDecoder = decoder
	return this
}

// OpaqueToken configures RFC 7662 opaque token introspection using the specified endpoint URI and client credentials.
func (this *OAuth2ResourceServerConfigurer) OpaqueToken(
	introspectionURI string,
	clientID string,
	clientSecret string,
) *OAuth2ResourceServerConfigurer {
	this.opaqueTokenIntrospector = NewNimbusOpaqueTokenIntrospector(
		introspectionURI,
		clientID,
		clientSecret,
	)
	return this
}

// OpaqueTokenIntrospector configures a custom OpaqueTokenIntrospector for opaque bearer token authentication.
func (this *OAuth2ResourceServerConfigurer) OpaqueTokenIntrospector(
	introspector OpaqueTokenIntrospector,
) *OAuth2ResourceServerConfigurer {
	this.opaqueTokenIntrospector = introspector
	return this
}

// Realm sets the realm name returned in WWW-Authenticate challenge headers.
func (this *OAuth2ResourceServerConfigurer) Realm(realm string) *OAuth2ResourceServerConfigurer {
	this.realmName = realm
	return this
}

// And registers the BearerTokenAuthenticationFilter configuration and returns the parent HttpSecurityBuilder.
func (this *OAuth2ResourceServerConfigurer) And() *HttpSecurityBuilder {
	cfg := &BearerTokenConfig{
		TokenResolver:           this.tokenResolver,
		AuthenticationManager:   this.authManager,
		SecurityContextHolder:   this.contextHolder,
		JwtDecoder:              this.jwtDecoder,
		OpaqueTokenIntrospector: this.opaqueTokenIntrospector,
		RealmName:               this.realmName,
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

// New creates a new OAuth2AuthorizationServerConfigurer attached to the given HttpSecurityBuilder.
func (this OAuth2AuthorizationServerConfigurer) New(builder *HttpSecurityBuilder) *OAuth2AuthorizationServerConfigurer {
	this.builder = builder
	return &this
}

// NewOAuth2AuthorizationServerConfigurer creates a new OAuth2AuthorizationServerConfigurer attached to the given HttpSecurityBuilder.
func NewOAuth2AuthorizationServerConfigurer(builder *HttpSecurityBuilder) *OAuth2AuthorizationServerConfigurer {
	return OAuth2AuthorizationServerConfigurer{}.New(builder)
}

// Settings sets the AuthorizationServerSettings defining endpoint URIs and issuer metadata.
func (this *OAuth2AuthorizationServerConfigurer) Settings(settings *AuthorizationServerSettings) *OAuth2AuthorizationServerConfigurer {
	this.settings = settings
	return this
}

// RegisteredClientRepository sets the repository used to look up registered OAuth 2.0 clients.
func (this *OAuth2AuthorizationServerConfigurer) RegisteredClientRepository(repo RegisteredClientRepository) *OAuth2AuthorizationServerConfigurer {
	this.clientRepo = repo
	return this
}

// AuthorizationService sets the OAuth2AuthorizationService used to manage authorization state and issued tokens.
func (this *OAuth2AuthorizationServerConfigurer) AuthorizationService(svc OAuth2AuthorizationService) *OAuth2AuthorizationServerConfigurer {
	this.authorizationService = svc
	return this
}

// TokenGenerator sets the OAuth2TokenGenerator used to issue access and refresh tokens.
func (this *OAuth2AuthorizationServerConfigurer) TokenGenerator(gen OAuth2TokenGenerator) *OAuth2AuthorizationServerConfigurer {
	this.tokenGenerator = gen
	return this
}

// JWKSource sets the JWKSource used for signing tokens and serving the JWKS endpoint.
func (this *OAuth2AuthorizationServerConfigurer) JWKSource(source JWKSource) *OAuth2AuthorizationServerConfigurer {
	this.jwkSource = source
	return this
}

// SecurityContextHolder sets the SecurityContextHolder used to inspect the authenticated resource owner during authorization.
func (this *OAuth2AuthorizationServerConfigurer) SecurityContextHolder(holder SecurityContextHolder) *OAuth2AuthorizationServerConfigurer {
	this.contextHolder = holder
	return this
}

// And registers the OAuth2AuthorizationServerFilter configuration and returns the parent HttpSecurityBuilder.
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

// OAuth2Login initiates OAuth 2.0 Login configuration on the given HttpSecurityBuilder.
func OAuth2Login(builder *HttpSecurityBuilder) *OAuth2LoginConfigurer {
	return OAuth2LoginConfigurer{}.New(builder)
}

var _ HttpSecurityBuilderOption = &OAuth2ResourceServerConfigurer{}

// OAuth2ResourceServer initiates OAuth 2.0 Resource Server configuration on the given HttpSecurityBuilder.
func OAuth2ResourceServer(builder *HttpSecurityBuilder) *OAuth2ResourceServerConfigurer {
	return OAuth2ResourceServerConfigurer{}.New(builder)
}

var _ HttpSecurityBuilderOption = &OAuth2AuthorizationServerConfigurer{}

// OAuth2AuthorizationServer initiates OAuth 2.1 Authorization Server configuration on the given HttpSecurityBuilder.
func OAuth2AuthorizationServer(builder *HttpSecurityBuilder) *OAuth2AuthorizationServerConfigurer {
	return OAuth2AuthorizationServerConfigurer{}.New(builder)
}

// Ensure unused import doesn't cause compiler error
var _ = http.StatusOK
