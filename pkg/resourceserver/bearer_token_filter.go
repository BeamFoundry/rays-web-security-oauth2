package resourceserver

import (
	"context"
	"fmt"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/auth"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// BearerTokenConfig holds configuration parameters for BearerTokenAuthenticationFilter
type BearerTokenConfig struct {
	TokenResolver           BearerTokenResolver
	AuthenticationManager   AuthenticationManager
	SecurityContextHolder   SecurityContextHolder
	JwtDecoder              JwtDecoder
	OpaqueTokenIntrospector OpaqueTokenIntrospector
	RealmName               string
}

// bearerAuthenticationManager delegates bearer token authentication across configured JWT, opaque token, and fallback providers.
type bearerAuthenticationManager struct {
	Manager
	jwtProvider    *JwtAuthenticationProvider
	opaqueProvider *OpaqueTokenAuthenticationProvider
	fallback       AuthenticationManager
}

// Authenticate attempts authentication using the configured JwtAuthenticationProvider, OpaqueTokenAuthenticationProvider, or fallback AuthenticationManager.
func (this *bearerAuthenticationManager) Authenticate(auth Authentication) (Authentication, AuthenticationException) {
	if this.jwtProvider != nil && this.jwtProvider.Supports(auth) {
		res, err := this.jwtProvider.Authenticate(auth)
		if err == nil {
			return res, nil
		}
		if this.opaqueProvider == nil && this.fallback == nil {
			return res, err
		}
	}
	if this.opaqueProvider != nil && this.opaqueProvider.Supports(auth) {
		res, err := this.opaqueProvider.Authenticate(auth)
		if err == nil {
			return res, nil
		}
		if this.fallback == nil {
			return res, err
		}
	}
	if this.fallback != nil {
		return this.fallback.Authenticate(auth)
	}
	return auth, ProviderNotFoundException{}.New("No AuthenticationProvider found for authentication", auth)
}

// BearerTokenAuthenticationFilter authenticates incoming requests containing a Bearer token
type BearerTokenAuthenticationFilter struct {
	Component
	Prototype
	tokenResolver           BearerTokenResolver
	authenticationManager   AuthenticationManager
	securityContextHolder   SecurityContextHolder
	jwtDecoder              JwtDecoder
	opaqueTokenIntrospector OpaqueTokenIntrospector
	config                  *BearerTokenConfig
	injectedTokenResolver   Optional[BearerTokenResolver]                `@:"Inject"`
	injectedAuthManager     Optional[AuthenticationManager]              `@:"Inject"`
	injectedContextHolder   Optional[SecurityContextHolder]              `@:"Inject"`
	injectedJwtDecoder      Optional[JwtDecoder]                         `@:"Inject"`
	injectedConverter       Optional[JwtAuthenticationConverter]         `@:"Inject"`
	injectedIntrospector    Optional[OpaqueTokenIntrospector]            `@:"Inject"`
	injectedOpaqueConverter Optional[OpaqueTokenAuthenticationConverter] `@:"Inject"`
	realmName               string
}

var (
	_, _                              = any(&BearerTokenAuthenticationFilter{}).(Stereotype)
	_    SecurityFilter               = &BearerTokenAuthenticationFilter{}
	_    BeamPostConstructWithContext = &BearerTokenAuthenticationFilter{}
)

// New creates a new BearerTokenAuthenticationFilter with a DefaultBearerTokenResolver and default realm name.
func (this BearerTokenAuthenticationFilter) New(
	authManager AuthenticationManager,
	contextHolder SecurityContextHolder,
) *BearerTokenAuthenticationFilter {
	this.tokenResolver = DefaultBearerTokenResolver{}.New()
	this.authenticationManager = authManager
	this.securityContextHolder = contextHolder
	this.realmName = "rays-web-security-oauth2"
	return &this
}

// NewBearerTokenAuthenticationFilter creates a new BearerTokenAuthenticationFilter.
func NewBearerTokenAuthenticationFilter(
	authManager AuthenticationManager,
	contextHolder SecurityContextHolder,
) *BearerTokenAuthenticationFilter {
	return BearerTokenAuthenticationFilter{}.New(authManager, contextHolder)
}

// WithTokenResolver sets the BearerTokenResolver used to extract bearer tokens from requests.
func (this *BearerTokenAuthenticationFilter) WithTokenResolver(resolver BearerTokenResolver) *BearerTokenAuthenticationFilter {
	this.tokenResolver = resolver
	return this
}

// WithRealmName sets the realm name included in WWW-Authenticate challenge headers.
func (this *BearerTokenAuthenticationFilter) WithRealmName(realm string) *BearerTokenAuthenticationFilter {
	this.realmName = realm
	return this
}

// WithJwtDecoder configures a JwtDecoder for JWT bearer token verification.
func (this *BearerTokenAuthenticationFilter) WithJwtDecoder(decoder JwtDecoder) *BearerTokenAuthenticationFilter {
	this.jwtDecoder = decoder
	return this
}

// WithOpaqueTokenIntrospector configures an OpaqueTokenIntrospector for RFC 7662 opaque token verification.
func (this *BearerTokenAuthenticationFilter) WithOpaqueTokenIntrospector(introspector OpaqueTokenIntrospector) *BearerTokenAuthenticationFilter {
	this.opaqueTokenIntrospector = introspector
	return this
}

// Config returns the effective BearerTokenConfig for this filter.
func (this *BearerTokenAuthenticationFilter) Config() *BearerTokenConfig {
	if this.config == nil {
		this.config = &BearerTokenConfig{
			TokenResolver:           this.tokenResolver,
			AuthenticationManager:   this.authenticationManager,
			SecurityContextHolder:   this.securityContextHolder,
			JwtDecoder:              this.jwtDecoder,
			OpaqueTokenIntrospector: this.opaqueTokenIntrospector,
			RealmName:               this.realmName,
		}
	}
	return this.config
}

// WithContext implements BeamPostConstructWithContext for prototype injection into HttpSecurity
func (this *BearerTokenAuthenticationFilter) WithContext(ctx context.Context) Error {
	if resolver, ok := this.injectedTokenResolver.Get(); ok {
		this.tokenResolver = resolver
	}
	if mgr, ok := this.injectedAuthManager.Get(); ok {
		this.authenticationManager = mgr
	}
	if holder, ok := this.injectedContextHolder.Get(); ok {
		this.securityContextHolder = holder
	}
	if dec, ok := this.injectedJwtDecoder.Get(); ok {
		this.jwtDecoder = dec
	}
	if intro, ok := this.injectedIntrospector.Get(); ok {
		this.opaqueTokenIntrospector = intro
	}

	if ct := ctx.Value(PrototypeContextParentInstance); ct != nil {
		httpSecurity, ok := ct.(*HttpSecurity)
		if !ok {
			return NewError("IllegalArgumentException", "Only HttpSecurity may inject this filter")
		}
		raw, ok := httpSecurity.SecurityFilters()["bearerTokenAuthenticationFilter"]
		if !ok {
			return NewError("IllegalArgumentException", "HttpSecurity does not configure bearerTokenAuthenticationFilter")
		}
		cfg, ok := raw.(*BearerTokenConfig)
		if !ok {
			return NewError("IllegalArgumentException", "Invalid configuration type for bearerTokenAuthenticationFilter")
		}
		this.config = cfg
		if cfg.TokenResolver != nil {
			this.tokenResolver = cfg.TokenResolver
		}
		if cfg.AuthenticationManager != nil {
			this.authenticationManager = cfg.AuthenticationManager
		}
		if cfg.SecurityContextHolder != nil {
			this.securityContextHolder = cfg.SecurityContextHolder
		}
		if cfg.JwtDecoder != nil {
			this.jwtDecoder = cfg.JwtDecoder
		}
		if cfg.OpaqueTokenIntrospector != nil {
			this.opaqueTokenIntrospector = cfg.OpaqueTokenIntrospector
		}
		if cfg.RealmName != "" {
			this.realmName = cfg.RealmName
		}
	}
	if this.tokenResolver == nil {
		this.tokenResolver = DefaultBearerTokenResolver{}.New()
	}
	if this.realmName == "" {
		this.realmName = "rays-web-security-oauth2"
	}

	var jwtProvider *JwtAuthenticationProvider
	if this.jwtDecoder != nil {
		jwtProvider = JwtAuthenticationProvider{}.New(this.jwtDecoder)
		if conv, ok := this.injectedConverter.Get(); ok {
			jwtProvider.WithConverter(conv)
		}
	}

	var opaqueProvider *OpaqueTokenAuthenticationProvider
	if this.opaqueTokenIntrospector != nil {
		opaqueProvider = OpaqueTokenAuthenticationProvider{}.New(this.opaqueTokenIntrospector)
		if conv, ok := this.injectedOpaqueConverter.Get(); ok {
			opaqueProvider.WithConverter(conv)
		}
	}

	if jwtProvider != nil || opaqueProvider != nil {
		this.authenticationManager = &bearerAuthenticationManager{
			jwtProvider:    jwtProvider,
			opaqueProvider: opaqueProvider,
			fallback:       this.authenticationManager,
		}
	}
	return nil
}

// Authenticate extracts Bearer token, invokes AuthenticationManager, and populates SecurityContextHolder
func (this *BearerTokenAuthenticationFilter) Authenticate(handler SecurityHandler) SecurityFilterChainException {
	token := this.tokenResolver.Resolve(handler)
	if token == "" {
		// No bearer token found, let downstream filters or anonymous evaluate
		return (&DefaultSecurityFilterChainException{}).Next()
	}

	authToken := BearerTokenAuthenticationToken{}.New(token)
	authenticated, authEx := this.authenticationManager.Authenticate(authToken)
	if authEx != nil {
		authEx.LogError()
		handler.SetHeader("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q, error="invalid_token", error_description=%q`, this.realmName, authEx.Message()))
		return (&DefaultSecurityFilterChainException{}).ReportError(authEx, 401)
	}

	if this.securityContextHolder != nil {
		ctx := this.securityContextHolder.GetContext()
		if ctx != nil {
			ctx.SetAuthentication(authenticated)
		}
	}

	return (&DefaultSecurityFilterChainException{}).Next()
}

// AuthenticationRequired issues 401 challenge with WWW-Authenticate header
func (this *BearerTokenAuthenticationFilter) AuthenticationRequired(handler SecurityHandler) SecurityFilterChainException {
	handler.SetHeader("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q`, this.realmName))
	err := NewError("AuthenticationRequiredException", "Authentication required")
	return (&DefaultSecurityFilterChainException{}).ReportError(err, 401)
}
