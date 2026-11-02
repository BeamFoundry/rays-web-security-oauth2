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
	TokenResolver         BearerTokenResolver
	AuthenticationManager AuthenticationManager
	SecurityContextHolder SecurityContextHolder
	JwtDecoder            JwtDecoder
	RealmName             string
}

type jwtAuthenticationManager struct {
	Manager
	provider *JwtAuthenticationProvider
	fallback AuthenticationManager
}

func (this *jwtAuthenticationManager) Authenticate(auth Authentication) (Authentication, AuthenticationException) {
	if this.provider != nil && this.provider.Supports(auth) {
		return this.provider.Authenticate(auth)
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
	tokenResolver         BearerTokenResolver
	authenticationManager AuthenticationManager
	securityContextHolder SecurityContextHolder
	jwtDecoder            JwtDecoder
	config                *BearerTokenConfig
	injectedTokenResolver Optional[BearerTokenResolver]        `@:"Inject"`
	injectedAuthManager   Optional[AuthenticationManager]      `@:"Inject"`
	injectedContextHolder Optional[SecurityContextHolder]      `@:"Inject"`
	injectedJwtDecoder    Optional[JwtDecoder]                 `@:"Inject"`
	injectedConverter     Optional[JwtAuthenticationConverter] `@:"Inject"`
	realmName             string
}

var (
	_, _                              = any(&BearerTokenAuthenticationFilter{}).(Stereotype)
	_    SecurityFilter               = &BearerTokenAuthenticationFilter{}
	_    BeamPostConstructWithContext = &BearerTokenAuthenticationFilter{}
)

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

func NewBearerTokenAuthenticationFilter(
	authManager AuthenticationManager,
	contextHolder SecurityContextHolder,
) *BearerTokenAuthenticationFilter {
	return BearerTokenAuthenticationFilter{}.New(authManager, contextHolder)
}

func (this *BearerTokenAuthenticationFilter) WithTokenResolver(resolver BearerTokenResolver) *BearerTokenAuthenticationFilter {
	this.tokenResolver = resolver
	return this
}

func (this *BearerTokenAuthenticationFilter) WithRealmName(realm string) *BearerTokenAuthenticationFilter {
	this.realmName = realm
	return this
}

func (this *BearerTokenAuthenticationFilter) WithJwtDecoder(decoder JwtDecoder) *BearerTokenAuthenticationFilter {
	this.jwtDecoder = decoder
	return this
}

func (this *BearerTokenAuthenticationFilter) Config() *BearerTokenConfig {
	if this.config == nil {
		this.config = &BearerTokenConfig{
			TokenResolver:         this.tokenResolver,
			AuthenticationManager: this.authenticationManager,
			SecurityContextHolder: this.securityContextHolder,
			JwtDecoder:            this.jwtDecoder,
			RealmName:             this.realmName,
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
	if this.jwtDecoder != nil {
		jwtProvider := JwtAuthenticationProvider{}.New(this.jwtDecoder)
		if conv, ok := this.injectedConverter.Get(); ok {
			jwtProvider.WithConverter(conv)
		}
		if this.authenticationManager == nil {
			this.authenticationManager = &jwtAuthenticationManager{provider: jwtProvider}
		} else {
			this.authenticationManager = &jwtAuthenticationManager{provider: jwtProvider, fallback: this.authenticationManager}
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
