package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2AuthorizationServerConfig holds configuration parameters for OAuth2AuthorizationServerFilter
type OAuth2AuthorizationServerConfig struct {
	Settings              *AuthorizationServerSettings
	ClientRepository      RegisteredClientRepository
	AuthorizationService  OAuth2AuthorizationService
	TokenGenerator        OAuth2TokenGenerator
	JWKSource             JWKSource
	SecurityContextHolder SecurityContextHolder
}

// OAuth2AuthorizationServerFilter handles OAuth 2.0 Authorization Server endpoints
type OAuth2AuthorizationServerFilter struct {
	clientRepo RegisteredClientRepository
	Prototype
	Component
	securityContextHolder  SecurityContextHolder
	jwkSource              JWKSource
	tokenGenerator         OAuth2TokenGenerator
	authorizationService   OAuth2AuthorizationService
	config                 *OAuth2AuthorizationServerConfig
	settings               *AuthorizationServerSettings
	codeMu                 *sync.Mutex
	injectedClientRepo     Optional[RegisteredClientRepository]   `@:"Inject"`
	injectedContextHolder  Optional[SecurityContextHolder]        `@:"Inject"`
	injectedJWKSource      Optional[JWKSource]                    `@:"Inject"`
	injectedTokenGenerator Optional[OAuth2TokenGenerator]         `@:"Inject"`
	injectedAuthService    Optional[OAuth2AuthorizationService]   `@:"Inject"`
	injectedSettings       Optional[*AuthorizationServerSettings] `@:"Inject"`
}

var (
	_, _                              = any(&OAuth2AuthorizationServerFilter{}).(Stereotype)
	_    SecurityFilter               = &OAuth2AuthorizationServerFilter{}
	_    SecurityEndpointRegistration = &OAuth2AuthorizationServerFilter{}
	_    BeamPostConstructWithContext = &OAuth2AuthorizationServerFilter{}
)

func (this OAuth2AuthorizationServerFilter) New(
	settings *AuthorizationServerSettings,
	clientRepo RegisteredClientRepository,
	authService OAuth2AuthorizationService,
	tokenGen OAuth2TokenGenerator,
	jwkSource JWKSource,
	contextHolder SecurityContextHolder,
) *OAuth2AuthorizationServerFilter {
	this.settings = settings
	this.clientRepo = clientRepo
	this.authorizationService = authService
	this.tokenGenerator = tokenGen
	this.jwkSource = jwkSource
	this.securityContextHolder = contextHolder
	this.codeMu = &sync.Mutex{}
	return &this
}

func NewOAuth2AuthorizationServerFilter(
	settings *AuthorizationServerSettings,
	clientRepo RegisteredClientRepository,
	authService OAuth2AuthorizationService,
	tokenGen OAuth2TokenGenerator,
	jwkSource JWKSource,
	contextHolder SecurityContextHolder,
) *OAuth2AuthorizationServerFilter {
	return OAuth2AuthorizationServerFilter{}.New(settings, clientRepo, authService, tokenGen, jwkSource, contextHolder)
}

func (this *OAuth2AuthorizationServerFilter) Config() *OAuth2AuthorizationServerConfig {
	if this.config == nil {
		this.config = &OAuth2AuthorizationServerConfig{
			Settings:              this.settings,
			ClientRepository:      this.clientRepo,
			AuthorizationService:  this.authorizationService,
			TokenGenerator:        this.tokenGenerator,
			JWKSource:             this.jwkSource,
			SecurityContextHolder: this.securityContextHolder,
		}
	}
	return this.config
}

// WithContext implements BeamPostConstructWithContext for prototype injection into HttpSecurity
func (this *OAuth2AuthorizationServerFilter) WithContext(ctx context.Context) Error {
	if s, ok := this.injectedSettings.Get(); ok {
		this.settings = s
	}
	if repo, ok := this.injectedClientRepo.Get(); ok {
		this.clientRepo = repo
	}
	if svc, ok := this.injectedAuthService.Get(); ok {
		this.authorizationService = svc
	}
	if gen, ok := this.injectedTokenGenerator.Get(); ok {
		this.tokenGenerator = gen
	}
	if src, ok := this.injectedJWKSource.Get(); ok {
		this.jwkSource = src
	}
	if holder, ok := this.injectedContextHolder.Get(); ok {
		this.securityContextHolder = holder
	}

	if ct := ctx.Value(PrototypeContextParentInstance); ct != nil {
		httpSecurity, ok := ct.(*HttpSecurity)
		if !ok {
			return NewError("IllegalArgumentException", "Only HttpSecurity may inject this filter")
		}
		raw, ok := httpSecurity.SecurityFilters()["oAuth2AuthorizationServerFilter"]
		if !ok {
			return NewError("IllegalArgumentException", "HttpSecurity does not configure oAuth2AuthorizationServerFilter")
		}
		cfg, ok := raw.(*OAuth2AuthorizationServerConfig)
		if !ok {
			return NewError("IllegalArgumentException", "Invalid configuration type for oAuth2AuthorizationServerFilter")
		}
		this.config = cfg
		if cfg.Settings != nil {
			this.settings = cfg.Settings
		}
		if cfg.ClientRepository != nil {
			this.clientRepo = cfg.ClientRepository
		}
		if cfg.AuthorizationService != nil {
			this.authorizationService = cfg.AuthorizationService
		}
		if cfg.TokenGenerator != nil {
			this.tokenGenerator = cfg.TokenGenerator
		}
		if cfg.JWKSource != nil {
			this.jwkSource = cfg.JWKSource
		}
		if cfg.SecurityContextHolder != nil {
			this.securityContextHolder = cfg.SecurityContextHolder
		}
	}
	if this.settings == nil {
		this.settings = AuthorizationServerSettings{}.NewDefault("http://localhost:8080")
	}
	if this.tokenGenerator == nil && this.jwkSource != nil {
		encoder := DefaultJwtEncoder{}.New(this.jwkSource)
		this.tokenGenerator = JwtOAuth2TokenGenerator{}.New(encoder, this.settings.Issuer)
	}
	return nil
}

// Authenticate is a no-op for authorization server endpoints (endpoints handle their own logic)
func (this *OAuth2AuthorizationServerFilter) Authenticate(_ SecurityHandler) SecurityFilterChainException {
	return (&DefaultSecurityFilterChainException{}).Next()
}

// AuthenticationRequired challenges unauthenticated access
func (this *OAuth2AuthorizationServerFilter) AuthenticationRequired(_ SecurityHandler) SecurityFilterChainException {
	return (&DefaultSecurityFilterChainException{}).ReportError(
		NewError("AuthenticationRequired", "Authentication required"),
		401,
	)
}

// RegisterSecurityEndpoint registers authorization server endpoints on the router
func (this *OAuth2AuthorizationServerFilter) RegisterSecurityEndpoint(router SecurityRouter) {
	// 1. Authorization Endpoint (GET /oauth2/authorize)
	router.Get(this.settings.AuthorizationEndpoint, this.handleAuthorize)

	// 2. Token Endpoint (POST /oauth2/token)
	router.Post(this.settings.TokenEndpoint, this.handleToken)

	// 3. JWK Set Endpoint (GET /oauth2/jwks)
	router.Get(this.settings.JwkSetEndpoint, this.handleJWKS)

	// 4. Discovery Metadata Endpoint (GET /.well-known/openid-configuration)
	router.Get(this.settings.OidcDiscoveryEndpoint, this.handleDiscovery)

	// 5. Token Introspection Endpoint (POST /oauth2/introspect)
	router.Post(this.settings.TokenIntrospectionEndpoint, this.handleIntrospect)

	// 6. Token Revocation Endpoint (POST /oauth2/revoke)
	router.Post(this.settings.TokenRevocationEndpoint, this.handleRevoke)
}

func (this *OAuth2AuthorizationServerFilter) handleAuthorize(handler SecurityHandler) error {
	q := handler.URL().Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	state := q.Get("state")
	scope := q.Get("scope")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	client, err := this.clientRepo.FindByClientID(clientID)
	if err != nil {
		err.LogError()
		return handler.Error(http.StatusBadRequest, "Unknown client_id: "+clientID)
	}

	if responseType != OAuth2ParameterCode {
		return handler.Error(http.StatusBadRequest, "Unsupported response_type: "+responseType)
	}

	if client.RequireProofKey && (codeChallenge == "" || codeChallengeMethod != "S256") {
		return handler.Error(http.StatusBadRequest, "PKCE with code_challenge_method=S256 is required")
	}

	// Verify user is authenticated in session
	var currentAuth Authentication
	if this.securityContextHolder != nil && this.securityContextHolder.GetContext() != nil {
		currentAuth = this.securityContextHolder.GetContext().GetAuthentication()
	}
	if currentAuth == nil || !currentAuth.IsAuthenticated() {
		// User must log in first
		handler.SetSessionValue("redirect", handler.Path()+"?"+handler.URL().RawQuery)
		return handler.Redirect("/login", http.StatusFound)
	}

	// Generate authorization code
	codeBytes := make([]byte, 32)
	if _, randErr := rand.Read(codeBytes); randErr != nil {
		NewErrorFrom(randErr).LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to generate code")
	}
	code := base64.RawURLEncoding.EncodeToString(codeBytes)

	now := time.Now()
	authCode := &AuthorizationCode{
		Value:               code,
		IssuedAt:            now,
		ExpiresAt:           now.Add(5 * time.Minute),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		RedirectURI:         redirectURI,
		Invalidated:         false,
	}

	var scopes []string
	if scope != "" {
		scopes = strings.Split(scope, " ")
	}

	authorization := &OAuth2Authorization{
		ID:                 fmt.Sprintf("auth-%d", now.UnixNano()),
		RegisteredClientID: client.ID,
		PrincipalName:      currentAuth.GetName(),
		AuthorizedScopes:   scopes,
		AuthorizationCode:  authCode,
	}

	if saveErr := this.authorizationService.Save(authorization); saveErr != nil {
		saveErr.LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to save authorization")
	}

	target := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, url.QueryEscape(code), url.QueryEscape(state))
	return handler.Redirect(target, http.StatusFound)
}

func (this *OAuth2AuthorizationServerFilter) handleToken(handler SecurityHandler) error {
	grantType := handler.FormValue("grant_type")
	clientID := handler.FormValue("client_id")
	clientSecret := handler.FormValue("client_secret")

	// Check Basic Auth header if form values absent
	authHeader := handler.Header("Authorization")
	if authHeader != "" && strings.HasPrefix(strings.ToLower(authHeader), "basic ") {
		payload, err := base64.StdEncoding.DecodeString(authHeader[6:])
		if err == nil {
			parts := strings.SplitN(string(payload), ":", 2)
			if len(parts) == 2 {
				clientID = parts[0]
				clientSecret = parts[1]
			}
		} else {
			NewErrorFrom(err).LogError()
		}
	}

	client, err := this.clientRepo.FindByClientID(clientID)
	if err != nil {
		err.LogError()
		return this.sendTokenError(handler, OAuth2ErrorInvalidClient, "Invalid client credentials")
	}

	// Authenticate client secret unless PKCE public client
	if !client.RequireProofKey && client.ClientSecret != "" && client.ClientSecret != clientSecret {
		return this.sendTokenError(handler, OAuth2ErrorInvalidClient, "Client authentication failed")
	}

	switch AuthorizationGrantType(grantType) {
	case GrantTypeAuthorizationCode:
		return this.handleAuthorizationCodeGrant(handler, client)
	case GrantTypeClientCredentials:
		return this.handleClientCredentialsGrant(handler, client)
	case GrantTypeRefreshToken:
		return this.handleRefreshTokenGrant(handler, client)
	default:
		return this.sendTokenError(handler, OAuth2ErrorUnsupportedGrantType, "Unsupported grant_type: "+grantType)
	}
}

func (this *OAuth2AuthorizationServerFilter) handleAuthorizationCodeGrant(handler SecurityHandler, client *RegisteredClient) error {
	if this.codeMu != nil {
		this.codeMu.Lock()
		defer this.codeMu.Unlock()
	}

	code := handler.FormValue(OAuth2ParameterCode)
	redirectURI := handler.FormValue("redirect_uri")
	codeVerifier := handler.FormValue("code_verifier")

	auth, err := this.authorizationService.FindByToken(code, OAuth2ParameterCode)
	if err != nil || auth == nil || auth.AuthorizationCode == nil {
		if err != nil {
			err.LogError()
		}
		return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Invalid or expired authorization code")
	}

	if auth.AuthorizationCode.Invalidated || time.Now().After(auth.AuthorizationCode.ExpiresAt) {
		return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Authorization code has expired or was already used")
	}

	if auth.AuthorizationCode.RedirectURI != "" && auth.AuthorizationCode.RedirectURI != redirectURI {
		return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Redirect URI mismatch")
	}

	// Verify PKCE
	if auth.AuthorizationCode.CodeChallenge != "" {
		hash := sha256.Sum256([]byte(codeVerifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		if expectedChallenge != auth.AuthorizationCode.CodeChallenge {
			return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "PKCE code_verifier validation failed")
		}
	}

	// Invalidate code
	auth.AuthorizationCode.Invalidated = true

	accessToken, refreshToken, err := this.tokenGenerator.Generate(auth, client)
	if err != nil {
		err.LogError()
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Token generation failed: "+err.Error())
	}

	auth.AccessToken = accessToken
	auth.RefreshToken = refreshToken
	if saveErr := this.authorizationService.Save(auth); saveErr != nil {
		saveErr.LogError()
	}

	return this.sendTokenSuccess(handler, accessToken, refreshToken)
}

func (this *OAuth2AuthorizationServerFilter) handleClientCredentialsGrant(handler SecurityHandler, client *RegisteredClient) error {
	hasGrant := slices.Contains(client.AuthorizationGrantTypes, GrantTypeClientCredentials)
	if !hasGrant {
		return this.sendTokenError(handler, OAuth2ErrorUnauthorizedClient, "Client not authorized for client_credentials")
	}

	now := time.Now()
	auth := &OAuth2Authorization{
		ID:                 fmt.Sprintf("auth-%d", now.UnixNano()),
		RegisteredClientID: client.ID,
		PrincipalName:      client.ClientID,
		AuthorizedScopes:   client.Scopes,
	}

	accessToken, _, err := this.tokenGenerator.Generate(auth, client)
	if err != nil {
		err.LogError()
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Token generation failed: "+err.Error())
	}

	auth.AccessToken = accessToken
	if saveErr := this.authorizationService.Save(auth); saveErr != nil {
		saveErr.LogError()
	}

	return this.sendTokenSuccess(handler, accessToken, nil)
}

func (this *OAuth2AuthorizationServerFilter) handleRefreshTokenGrant(handler SecurityHandler, client *RegisteredClient) error {
	refreshTokenVal := handler.FormValue("refresh_token")
	auth, err := this.authorizationService.FindByToken(refreshTokenVal, "refresh_token")
	if err != nil || auth == nil || auth.RefreshToken == nil {
		if err != nil {
			err.LogError()
		}
		return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Invalid refresh_token")
	}

	accessToken, newRefreshToken, err := this.tokenGenerator.Generate(auth, client)
	if err != nil {
		err.LogError()
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Token generation failed")
	}

	auth.AccessToken = accessToken
	if newRefreshToken != nil {
		auth.RefreshToken = newRefreshToken
	}
	if saveErr := this.authorizationService.Save(auth); saveErr != nil {
		saveErr.LogError()
	}

	return this.sendTokenSuccess(handler, accessToken, auth.RefreshToken)
}

func (this *OAuth2AuthorizationServerFilter) handleJWKS(handler SecurityHandler) error {
	jwkSet, err := this.jwkSource.GetJWKSet()
	if err != nil {
		err.LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to retrieve JWK set")
	}
	handler.SetHeader("Content-Type", "application/json")
	bytes, jsonErr := json.Marshal(jwkSet)
	if jsonErr != nil {
		NewErrorFrom(jsonErr).LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to serialize JWK set")
	}
	if _, writeErr := handler.Write(bytes); writeErr != nil {
		NewErrorFrom(writeErr).LogError()
	}
	return nil
}

func (this *OAuth2AuthorizationServerFilter) handleDiscovery(handler SecurityHandler) error {
	meta := map[string]any{
		"issuer":                                this.settings.Issuer,
		"authorization_endpoint":                this.settings.Issuer + this.settings.AuthorizationEndpoint,
		"token_endpoint":                        this.settings.Issuer + this.settings.TokenEndpoint,
		"jwks_uri":                              this.settings.Issuer + this.settings.JwkSetEndpoint,
		"revocation_endpoint":                   this.settings.Issuer + this.settings.TokenRevocationEndpoint,
		"introspection_endpoint":                this.settings.Issuer + this.settings.TokenIntrospectionEndpoint,
		"response_types_supported":              []string{OAuth2ParameterCode},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}

	handler.SetHeader("Content-Type", "application/json")
	bytes, jsonErr := json.Marshal(meta)
	if jsonErr != nil {
		NewErrorFrom(jsonErr).LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to serialize discovery metadata")
	}
	if _, writeErr := handler.Write(bytes); writeErr != nil {
		NewErrorFrom(writeErr).LogError()
	}
	return nil
}

func (this *OAuth2AuthorizationServerFilter) handleIntrospect(handler SecurityHandler) error {
	token := handler.FormValue("token")
	auth, err := this.authorizationService.FindByToken(token, "access_token")
	if err != nil {
		err.LogError()
	}

	resp := map[string]any{"active": false}
	if err == nil && auth != nil && auth.AccessToken != nil && !auth.AccessToken.IsExpired() {
		resp["active"] = true
		resp["sub"] = auth.PrincipalName
		clientID := auth.RegisteredClientID
		if client, clientErr := this.clientRepo.FindByID(auth.RegisteredClientID); clientErr == nil {
			clientID = client.ClientID
		} else {
			clientErr.LogError()
		}
		resp["client_id"] = clientID
		resp["scope"] = strings.Join(auth.AuthorizedScopes, " ")
		resp["exp"] = auth.AccessToken.ExpiresAt.Unix()
	}

	handler.SetHeader("Content-Type", "application/json")
	bytes, jsonErr := json.Marshal(resp)
	if jsonErr != nil {
		NewErrorFrom(jsonErr).LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to serialize introspection response")
	}
	if _, writeErr := handler.Write(bytes); writeErr != nil {
		NewErrorFrom(writeErr).LogError()
	}
	return nil
}

func (this *OAuth2AuthorizationServerFilter) handleRevoke(handler SecurityHandler) error {
	token := handler.FormValue("token")
	if auth, err := this.authorizationService.FindByToken(token, "access_token"); err == nil {
		if rmErr := this.authorizationService.Remove(auth); rmErr != nil {
			rmErr.LogError()
		}
	} else {
		err.LogError()
		if auth, err := this.authorizationService.FindByToken(token, "refresh_token"); err == nil {
			if rmErr := this.authorizationService.Remove(auth); rmErr != nil {
				rmErr.LogError()
			}
		} else {
			err.LogError()
		}
	}
	handler.SetHeader("Content-Type", "application/json")
	if _, writeErr := handler.Write([]byte("{}")); writeErr != nil {
		NewErrorFrom(writeErr).LogError()
	}
	return nil
}

func (this *OAuth2AuthorizationServerFilter) sendTokenSuccess(handler SecurityHandler, access *OAuth2AccessToken, refresh *OAuth2RefreshToken) error {
	handler.SetHeader("Content-Type", "application/json")
	handler.SetHeader("Cache-Control", "no-store")
	handler.SetHeader("Pragma", "no-cache")

	resp := map[string]any{
		"access_token": access.TokenValue,
		"token_type":   string(access.TokenType),
		"expires_in":   int64(time.Until(access.ExpiresAt).Seconds()),
	}
	if len(access.Scopes) > 0 {
		resp["scope"] = strings.Join(access.Scopes, " ")
	}
	if refresh != nil && refresh.TokenValue != "" {
		resp["refresh_token"] = refresh.TokenValue
	}

	bytes, jsonErr := json.Marshal(resp)
	if jsonErr != nil {
		err := NewErrorFrom(jsonErr)
		err.LogError()
		return err
	}
	_, writeErr := handler.Write(bytes)
	if writeErr != nil {
		err := NewErrorFrom(writeErr)
		err.LogError()
		return err
	}
	return nil
}

func (this *OAuth2AuthorizationServerFilter) sendTokenError(handler SecurityHandler, errCode, errDesc string) error {
	handler.SetHeader("Content-Type", "application/json")
	resp := map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	}
	bytes, jsonErr := json.Marshal(resp)
	if jsonErr != nil {
		NewErrorFrom(jsonErr).LogError()
	}
	if _, writeErr := handler.Write(bytes); writeErr != nil {
		NewErrorFrom(writeErr).LogError()
	}
	return handler.Error(http.StatusBadRequest, errDesc)
}
