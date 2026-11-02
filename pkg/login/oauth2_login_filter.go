package login

import (
	"context"
	"fmt"
	"strings"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2LoginConfig holds configuration parameters for OAuth2LoginAuthenticationFilter
type OAuth2LoginConfig struct {
	ClientRegistrationRepository ClientRegistrationRepository
	AuthRequestRepository        AuthorizationRequestRepository
	AuthenticationManager        AuthenticationManager
	SecurityContextHolder        SecurityContextHolder
	DefaultRegistrationID        string
	DefaultSuccessURL            string
	LoginProcessingURL           string
	AuthorizationBaseURI         string
	BaseURL                      string
	TrustedProxy                 bool
}

// OAuth2LoginAuthenticationFilter handles OAuth2 authorization request redirection and code callback processing
type OAuth2LoginAuthenticationFilter struct {
	authRequestRepo AuthorizationRequestRepository
	Prototype
	SessionAwareFilter
	Component
	securityContextHolder  SecurityContextHolder
	authenticationManager  AuthenticationManager
	clientRegistrationRepo ClientRegistrationRepository
	config                 *OAuth2LoginConfig
	injectedAuthReqRepo    Optional[AuthorizationRequestRepository] `@:"Inject"`
	injectedContextHolder  Optional[SecurityContextHolder]          `@:"Inject"`
	injectedAuthManager    Optional[AuthenticationManager]          `@:"Inject"`
	injectedClientRepo     Optional[ClientRegistrationRepository]   `@:"Inject"`
	defaultRegistrationID  string
	defaultSuccessURL      string
	loginProcessingURL     string
	authorizationBaseURI   string
	baseURL                string
	trustedProxy           bool
}

var _, _ = any(&OAuth2LoginAuthenticationFilter{}).(Stereotype)

var _ SecurityFilter = &OAuth2LoginAuthenticationFilter{}

var _ SecurityEndpointRegistration = &OAuth2LoginAuthenticationFilter{}

var _ BeamPostConstructWithContext = &OAuth2LoginAuthenticationFilter{}

func (this OAuth2LoginAuthenticationFilter) New(
	clientRepo ClientRegistrationRepository,
	authManager AuthenticationManager,
	contextHolder SecurityContextHolder,
) *OAuth2LoginAuthenticationFilter {
	this.clientRegistrationRepo = clientRepo
	this.authRequestRepo = SessionAuthorizationRequestRepository{}.New()
	this.authenticationManager = authManager
	this.securityContextHolder = contextHolder
	this.defaultSuccessURL = "/"
	this.loginProcessingURL = "/login/oauth2/code/"
	this.authorizationBaseURI = "/oauth2/authorization/"
	return &this
}

func NewOAuth2LoginAuthenticationFilter(
	clientRepo ClientRegistrationRepository,
	authManager AuthenticationManager,
	contextHolder SecurityContextHolder,
) *OAuth2LoginAuthenticationFilter {
	return OAuth2LoginAuthenticationFilter{}.New(clientRepo, authManager, contextHolder)
}

func (this *OAuth2LoginAuthenticationFilter) WithDefaultRegistrationID(id string) *OAuth2LoginAuthenticationFilter {
	this.defaultRegistrationID = id
	return this
}

func (this *OAuth2LoginAuthenticationFilter) WithDefaultSuccessURL(url string) *OAuth2LoginAuthenticationFilter {
	this.defaultSuccessURL = url
	return this
}

func (this *OAuth2LoginAuthenticationFilter) WithBaseURL(url string) *OAuth2LoginAuthenticationFilter {
	this.baseURL = url
	return this
}

func (this *OAuth2LoginAuthenticationFilter) WithTrustedProxy(trusted bool) *OAuth2LoginAuthenticationFilter {
	this.trustedProxy = trusted
	return this
}

func (this *OAuth2LoginAuthenticationFilter) Config() *OAuth2LoginConfig {
	if this.config == nil {
		this.config = &OAuth2LoginConfig{
			ClientRegistrationRepository: this.clientRegistrationRepo,
			AuthRequestRepository:        this.authRequestRepo,
			AuthenticationManager:        this.authenticationManager,
			SecurityContextHolder:        this.securityContextHolder,
			DefaultRegistrationID:        this.defaultRegistrationID,
			DefaultSuccessURL:            this.defaultSuccessURL,
			LoginProcessingURL:           this.loginProcessingURL,
			AuthorizationBaseURI:         this.authorizationBaseURI,
			BaseURL:                      this.baseURL,
			TrustedProxy:                 this.trustedProxy,
		}
	}
	return this.config
}

// WithContext implements BeamPostConstructWithContext for prototype injection into HttpSecurity
func (this *OAuth2LoginAuthenticationFilter) WithContext(ctx context.Context) Error {
	if repo, ok := this.injectedClientRepo.Get(); ok {
		this.clientRegistrationRepo = repo
	}
	if repo, ok := this.injectedAuthReqRepo.Get(); ok {
		this.authRequestRepo = repo
	}
	if mgr, ok := this.injectedAuthManager.Get(); ok {
		this.authenticationManager = mgr
	}
	if holder, ok := this.injectedContextHolder.Get(); ok {
		this.securityContextHolder = holder
	}

	if ct := ctx.Value(PrototypeContextParentInstance); ct != nil {
		httpSecurity, ok := ct.(*HttpSecurity)
		if !ok {
			return NewError("IllegalArgumentException", "Only HttpSecurity may inject this filter")
		}
		raw, ok := httpSecurity.SecurityFilters()["oAuth2LoginAuthenticationFilter"]
		if !ok {
			return NewError("IllegalArgumentException", "HttpSecurity does not configure oAuth2LoginAuthenticationFilter")
		}
		cfg, ok := raw.(*OAuth2LoginConfig)
		if !ok {
			return NewError("IllegalArgumentException", "Invalid configuration type for oAuth2LoginAuthenticationFilter")
		}
		this.config = cfg
		if cfg.ClientRegistrationRepository != nil {
			this.clientRegistrationRepo = cfg.ClientRegistrationRepository
		}
		if cfg.AuthRequestRepository != nil {
			this.authRequestRepo = cfg.AuthRequestRepository
		}
		if cfg.AuthenticationManager != nil {
			this.authenticationManager = cfg.AuthenticationManager
		}
		if cfg.SecurityContextHolder != nil {
			this.securityContextHolder = cfg.SecurityContextHolder
		}
		if cfg.DefaultRegistrationID != "" {
			this.defaultRegistrationID = cfg.DefaultRegistrationID
		}
		if cfg.DefaultSuccessURL != "" {
			this.defaultSuccessURL = cfg.DefaultSuccessURL
		}
		if cfg.LoginProcessingURL != "" {
			this.loginProcessingURL = cfg.LoginProcessingURL
		}
		if cfg.AuthorizationBaseURI != "" {
			this.authorizationBaseURI = cfg.AuthorizationBaseURI
		}
		if cfg.BaseURL != "" {
			this.baseURL = cfg.BaseURL
		}
		this.trustedProxy = cfg.TrustedProxy
	}
	if this.authRequestRepo == nil {
		this.authRequestRepo = SessionAuthorizationRequestRepository{}.New()
	}
	if this.defaultSuccessURL == "" {
		this.defaultSuccessURL = "/"
	}
	if this.loginProcessingURL == "" {
		this.loginProcessingURL = "/login/oauth2/code/"
	}
	if this.authorizationBaseURI == "" {
		this.authorizationBaseURI = "/oauth2/authorization/"
	}
	return nil
}

// RegisterSecurityEndpoint registers authorization redirection and callback endpoints
func (this *OAuth2LoginAuthenticationFilter) RegisterSecurityEndpoint(router SecurityRouter) {
	// 1. Authorization initiation endpoint: /oauth2/authorization/{registrationId}
	router.Use(func(handler SecurityHandler) error {
		path := handler.Path()
		if after, ok := strings.CutPrefix(path, this.authorizationBaseURI); ok {
			registrationID := after
			reg, err := this.clientRegistrationRepo.FindByRegistrationID(registrationID)
			if err != nil {
				err.LogError()
				return handler.Error(404, "Client registration not found: "+registrationID)
			}

			authReq, genErr := GenerateAuthorizationRequest(
				reg,
				handler,
				WithBaseURL(this.baseURL),
				WithTrustedProxy(this.trustedProxy),
			)
			if genErr != nil {
				genErr.LogError()
				return handler.Error(500, "Failed to generate authorization request: "+genErr.Error())
			}

			this.authRequestRepo.SaveAuthorizationRequest(authReq, handler)
			targetURI := BuildAuthorizationURI(authReq)
			return handler.Redirect(targetURI, 302)
		}
		return handler.Next()
	})
}

// Authenticate intercepts OAuth2 callback requests
func (this *OAuth2LoginAuthenticationFilter) Authenticate(handler SecurityHandler) SecurityFilterChainException {
	path := handler.Path()
	if !strings.HasPrefix(path, this.loginProcessingURL) {
		return (&DefaultSecurityFilterChainException{}).Next()
	}

	registrationID := strings.TrimPrefix(path, this.loginProcessingURL)
	reg, err := this.clientRegistrationRepo.FindByRegistrationID(registrationID)
	if err != nil {
		err.LogError()
		errObj := NewError("OAuth2AuthenticationError", "Registration ID not found: "+registrationID)
		return (&DefaultSecurityFilterChainException{}).ReportError(errObj, 400)
	}

	u := handler.URL()
	q := u.Query()
	code := q.Get("code")
	state := q.Get("state")
	errCode := q.Get("error")

	if errCode != "" {
		errDesc := q.Get("error_description")
		errObj := NewError("OAuth2AuthenticationError", fmt.Sprintf("IdP error: %s - %s", errCode, errDesc))
		return (&DefaultSecurityFilterChainException{}).ReportError(errObj, 401)
	}

	savedReq := this.authRequestRepo.RemoveAuthorizationRequest(handler)
	if savedReq == nil {
		errObj := NewError("OAuth2AuthenticationError", "No authorization request found in session")
		return (&DefaultSecurityFilterChainException{}).ReportError(errObj, 400)
	}

	if savedReq.State != state {
		errObj := NewError("OAuth2AuthenticationError", "Invalid state parameter: CSRF detected")
		return (&DefaultSecurityFilterChainException{}).ReportError(errObj, 400)
	}

	exchange := OAuth2AuthorizationExchange{
		AuthorizationRequest: savedReq,
		AuthorizationResponse: &OAuth2AuthorizationResponse{
			Code:        code,
			State:       state,
			RedirectURI: savedReq.RedirectURI,
		},
	}

	unauthenticated := OAuth2LoginAuthenticationToken{}.New(reg, exchange)
	authenticated, authEx := this.authenticationManager.Authenticate(unauthenticated)
	if authEx != nil {
		authEx.LogError()
		return (&DefaultSecurityFilterChainException{}).ReportError(authEx, 401)
	}

	// Session refresh & store authenticated user
	handler.SessionRefresh()
	handler.SetSessionValue("authentication", authenticated)

	if this.securityContextHolder != nil {
		ctx := this.securityContextHolder.GetContext()
		if ctx != nil {
			ctx.SetAuthentication(authenticated)
		}
	}

	targetURL := this.defaultSuccessURL
	if redirect, ok := handler.SessionValue("redirect").(string); ok && redirect != "" {
		targetURL = redirect
		handler.SetSessionValue("redirect", nil)
	}

	return (&DefaultSecurityFilterChainException{}).RedirectTo(targetURL)
}

// AuthenticationRequired redirects unauthenticated requests to the authorization endpoint
func (this *OAuth2LoginAuthenticationFilter) AuthenticationRequired(handler SecurityHandler) SecurityFilterChainException {
	if handler.Method() == "GET" {
		handler.SetSessionValue("redirect", handler.Path())
	}

	regID := this.defaultRegistrationID
	if regID == "" {
		regID = "default"
	}

	return (&DefaultSecurityFilterChainException{}).RedirectTo(this.authorizationBaseURI + regID)
}
