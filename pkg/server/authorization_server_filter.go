package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
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

	randRead    = rand.Read
	jsonMarshal = json.Marshal
)

// New creates a new OAuth2AuthorizationServerFilter with the provided settings, repositories, services, and key source.
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
	return &this
}

// NewOAuth2AuthorizationServerFilter creates a new OAuth2AuthorizationServerFilter.
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

// Config returns the supplied OAuth2AuthorizationServerConfig or a lazily created snapshot of the filter's fields, not necessarily the effective configuration after WithContext injects dependencies.
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

// handleAuthorize processes OAuth 2.0 authorization requests at the authorization endpoint.
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

	if !slices.Contains(client.AuthorizationGrantTypes, GrantTypeAuthorizationCode) {
		return handler.Error(http.StatusBadRequest, "Client is not authorized for authorization_code grant")
	}

	redirectURISupplied := redirectURI != ""
	if !redirectURISupplied {
		if len(client.RedirectURIs) != 1 {
			return handler.Error(http.StatusBadRequest, "Missing redirect_uri and client does not have exactly one registered redirect URI")
		}
		redirectURI = client.RedirectURIs[0]
	} else if !slices.Contains(client.RedirectURIs, redirectURI) {
		return handler.Error(http.StatusBadRequest, "Invalid redirect_uri: "+redirectURI)
	}

	if responseType != OAuth2ParameterCode {
		return handler.Error(http.StatusBadRequest, "Unsupported response_type: "+responseType)
	}

	if (client.RequireProofKey && codeChallenge == "") || (codeChallenge != "" && codeChallengeMethod != "S256") {
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

	// Validate requested scopes against registered scopes
	var scopes []string
	if scope != "" {
		requestedScopes := strings.SplitSeq(scope, " ")
		for s := range requestedScopes {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !slices.Contains(client.Scopes, s) {
				return handler.Error(http.StatusBadRequest, "Unauthorized or unconfigured scope: "+s)
			}
			scopes = append(scopes, s)
		}
	} else {
		scopes = client.Scopes
	}

	// Generate authorization code
	codeBytes := make([]byte, 32)
	if _, randErr := randRead(codeBytes); randErr != nil {
		NewErrorFrom(randErr).LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to generate authorization code")
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
		RedirectURISupplied: redirectURISupplied,
		Invalidated:         false,
	}

	authIDBytes := make([]byte, 16)
	if _, randErr := randRead(authIDBytes); randErr != nil {
		NewErrorFrom(randErr).LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to generate authorization ID")
	}

	authorization := &OAuth2Authorization{
		ID:                 "auth-" + base64.RawURLEncoding.EncodeToString(authIDBytes),
		RegisteredClientID: client.ID,
		PrincipalName:      currentAuth.GetName(),
		AuthorizedScopes:   scopes,
		AuthorizationCode:  authCode,
	}

	if saveErr := this.authorizationService.Save(authorization); saveErr != nil {
		saveErr.LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to save authorization")
	}

	targetURL, parseErr := url.Parse(redirectURI)
	if parseErr != nil {
		NewErrorFrom(parseErr).LogError()
		return handler.Error(http.StatusBadRequest, "Malformed redirect_uri: "+redirectURI)
	}
	tQuery := targetURL.Query()
	tQuery.Set("code", code)
	if state != "" {
		tQuery.Set("state", state)
	}
	targetURL.RawQuery = tQuery.Encode()
	return handler.Redirect(targetURL.String(), http.StatusFound)
}

// isPublicClient reports whether the registered client is a public client that authenticates with "none" and has no secret-based authentication method.
func isPublicClient(client *RegisteredClient) bool {
	if len(client.ClientAuthenticationMethods) > 0 {
		return slices.Contains(client.ClientAuthenticationMethods, ClientAuthMethodNone) &&
			!slices.Contains(client.ClientAuthenticationMethods, ClientAuthMethodBasic) &&
			!slices.Contains(client.ClientAuthenticationMethods, ClientAuthMethodPost)
	}
	return client.ClientSecret == ""
}

// authenticateClient extracts and verifies client credentials from HTTP Basic auth or form parameters.
func (this *OAuth2AuthorizationServerFilter) authenticateClient(handler SecurityHandler) (*RegisteredClient, Error) {
	clientID := handler.FormValue("client_id")
	clientSecret := handler.FormValue("client_secret")

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

	if clientID == "" {
		return nil, NewError("InvalidClientError", "Client ID is required")
	}

	client, err := this.clientRepo.FindByClientID(clientID)
	if err != nil {
		return nil, err
	}

	if !isPublicClient(client) {
		if client.ClientSecret == "" || clientSecret == "" ||
			subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
			return nil, NewError("InvalidClientError", "Client authentication failed")
		}
	}

	return client, nil
}

// handleToken processes OAuth 2.0 token requests at the token endpoint and dispatches by grant_type.
func (this *OAuth2AuthorizationServerFilter) handleToken(handler SecurityHandler) error {
	grantType := handler.FormValue("grant_type")

	client, err := this.authenticateClient(handler)
	if err != nil {
		err.LogError()
		return this.sendTokenError(handler, OAuth2ErrorInvalidClient, "Invalid client credentials")
	}

	if isPublicClient(client) {
		if grantType != string(GrantTypeAuthorizationCode) && grantType != string(GrantTypeRefreshToken) {
			return this.sendTokenError(handler, OAuth2ErrorUnauthorizedClient, "Public clients may only use authorization_code and refresh_token grants")
		}
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

// handleAuthorizationCodeGrant validates an authorization code, redirect URI, and PKCE verifier, and issues access and refresh tokens.
func (this *OAuth2AuthorizationServerFilter) handleAuthorizationCodeGrant(handler SecurityHandler, client *RegisteredClient) error {
	code := handler.FormValue(OAuth2ParameterCode)
	redirectURI := handler.FormValue("redirect_uri")
	codeVerifier := handler.FormValue("code_verifier")

	auth, err := this.authorizationService.InvalidateAuthorizationCode(code)
	if err != nil || auth == nil || auth.AuthorizationCode == nil {
		if err != nil {
			err.LogError()
		}
		return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Authorization code has expired or was already used")
	}

	if auth.RegisteredClientID != client.ID && auth.RegisteredClientID != client.ClientID {
		return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Client ID does not match authorization code")
	}

	if auth.AuthorizationCode.RedirectURISupplied {
		if redirectURI != auth.AuthorizationCode.RedirectURI {
			return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Redirect URI mismatch")
		}
	} else if redirectURI != "" && redirectURI != auth.AuthorizationCode.RedirectURI {
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

	accessToken, refreshToken, err := this.tokenGenerator.Generate(auth, client)
	if err != nil {
		err.LogError()
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Token generation failed: "+err.Error())
	}

	auth.AccessToken = accessToken
	auth.RefreshToken = refreshToken
	if saveErr := this.authorizationService.Save(auth); saveErr != nil {
		saveErr.LogError()
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Failed to save authorization")
	}

	return this.sendTokenSuccess(handler, accessToken, refreshToken)
}

// handleClientCredentialsGrant executes the client_credentials grant and issues an access token for the authenticated client.
func (this *OAuth2AuthorizationServerFilter) handleClientCredentialsGrant(handler SecurityHandler, client *RegisteredClient) error {
	hasGrant := slices.Contains(client.AuthorizationGrantTypes, GrantTypeClientCredentials)
	if !hasGrant {
		return this.sendTokenError(handler, OAuth2ErrorUnauthorizedClient, "Client not authorized for client_credentials")
	}

	authIDBytes := make([]byte, 16)
	if _, randErr := randRead(authIDBytes); randErr != nil {
		NewErrorFrom(randErr).LogError()
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Failed to generate authorization ID")
	}

	auth := &OAuth2Authorization{
		ID:                 "auth-" + base64.RawURLEncoding.EncodeToString(authIDBytes),
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
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Failed to save authorization")
	}

	return this.sendTokenSuccess(handler, accessToken, nil)
}

// handleRefreshTokenGrant consumes a refresh token and issues rotated access and refresh tokens.
func (this *OAuth2AuthorizationServerFilter) handleRefreshTokenGrant(handler SecurityHandler, client *RegisteredClient) error {
	if !slices.Contains(client.AuthorizationGrantTypes, GrantTypeRefreshToken) {
		return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Client not registered for refresh_token grant")
	}

	refreshTokenVal := handler.FormValue("refresh_token")
	auth, err := this.authorizationService.ConsumeRefreshToken(refreshTokenVal)
	if err != nil || auth == nil || auth.RefreshToken == nil {
		if err != nil {
			err.LogError()
		}
		return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Invalid refresh_token")
	}

	if auth.RegisteredClientID != client.ID && auth.RegisteredClientID != client.ClientID {
		return this.sendTokenError(handler, OAuth2ErrorInvalidGrant, "Client ID does not match refresh token")
	}

	accessToken, newRefreshToken, err := this.tokenGenerator.Generate(auth, client)
	if err != nil {
		err.LogError()
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Token generation failed")
	}

	if saveErr := this.authorizationService.SaveTokens(auth.ID, refreshTokenVal, accessToken, newRefreshToken); saveErr != nil {
		saveErr.LogError()
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Failed to save updated tokens")
	}

	outRefreshToken := newRefreshToken
	if outRefreshToken == nil {
		outRefreshToken = auth.RefreshToken
	}

	return this.sendTokenSuccess(handler, accessToken, outRefreshToken)
}

// handleJWKS serves the public JSON Web Key Set at the JWKS endpoint.
func (this *OAuth2AuthorizationServerFilter) handleJWKS(handler SecurityHandler) error {
	jwkSet, err := this.jwkSource.GetJWKSet()
	if err != nil {
		err.LogError()
		return handler.Error(http.StatusInternalServerError, "Failed to retrieve JWK set")
	}
	handler.SetHeader("Content-Type", "application/json")
	Try(func() {
		bytes := RaiseVal(json.Marshal(jwkSet))
		_, writeErr := handler.Write(bytes)
		RaiseNilErr(writeErr)
	}).LogError()
	return nil
}

// handleDiscovery serves OAuth 2.0 Authorization Server / OpenID Provider metadata at the discovery endpoint.
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
	Try(func() {
		bytes := RaiseVal(json.Marshal(meta))
		_, writeErr := handler.Write(bytes)
		RaiseNilErr(writeErr)
	}).LogError()
	return nil
}

// handleIntrospect processes RFC 7662 token introspection requests.
func (this *OAuth2AuthorizationServerFilter) handleIntrospect(handler SecurityHandler) error {
	_, err := this.authenticateClient(handler)
	if err != nil {
		err.LogError()
		return this.sendTokenError(handler, OAuth2ErrorInvalidClient, "Client authentication failed")
	}

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
		if registered, clientErr := this.clientRepo.FindByID(auth.RegisteredClientID); clientErr == nil {
			clientID = registered.ClientID
		} else {
			clientErr.LogError()
		}
		resp["client_id"] = clientID
		resp["scope"] = strings.Join(auth.AuthorizedScopes, " ")
		resp["exp"] = auth.AccessToken.ExpiresAt.Unix()
	}

	handler.SetHeader("Content-Type", "application/json")
	Try(func() {
		bytes := RaiseVal(json.Marshal(resp))
		_, writeErr := handler.Write(bytes)
		RaiseNilErr(writeErr)
	}).LogError()
	return nil
}

// handleRevoke processes RFC 7009 token revocation requests for access or refresh tokens owned by the authenticated client.
func (this *OAuth2AuthorizationServerFilter) handleRevoke(handler SecurityHandler) error {
	client, err := this.authenticateClient(handler)
	if err != nil {
		err.LogError()
		return this.sendTokenError(handler, OAuth2ErrorInvalidClient, "Client authentication failed")
	}

	token := handler.FormValue("token")
	if token != "" {
		auth, findErr := this.authorizationService.FindByToken(token, "access_token")
		if findErr != nil && findErr.Name() != "AuthorizationNotFound" {
			findErr.LogError()
			return handler.Error(http.StatusInternalServerError, "Failed to lookup token")
		}
		if auth != nil {
			if auth.RegisteredClientID == client.ID || auth.RegisteredClientID == client.ClientID {
				if rmErr := this.authorizationService.Remove(auth); rmErr != nil {
					rmErr.LogError()
					return handler.Error(http.StatusInternalServerError, "Failed to revoke token")
				}
			}
		} else {
			authRT, rtErr := this.authorizationService.FindByToken(token, "refresh_token")
			if rtErr != nil && rtErr.Name() != "AuthorizationNotFound" {
				rtErr.LogError()
				return handler.Error(http.StatusInternalServerError, "Failed to lookup token")
			}
			if authRT != nil {
				if authRT.RegisteredClientID == client.ID || authRT.RegisteredClientID == client.ClientID {
					if rmErr := this.authorizationService.Remove(authRT); rmErr != nil {
						rmErr.LogError()
						return handler.Error(http.StatusInternalServerError, "Failed to revoke token")
					}
				}
			}
		}
	}
	handler.SetHeader("Content-Type", "application/json")
	Try(func() {
		_, writeErr := handler.Write([]byte("{}"))
		RaiseNilErr(writeErr)
	}).LogError()
	return nil
}

// sendTokenSuccess writes a successful RFC 6749 JSON token response with no-store cache headers.
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

	bytes, marshalErr := jsonMarshal(resp)
	if marshalErr != nil {
		NewErrorFrom(marshalErr).LogError()
		return this.sendTokenError(handler, OAuth2ErrorServerError, "Failed to serialize token response")
	}
	if _, writeErr := handler.Write(bytes); writeErr != nil {
		return writeErr
	}
	return nil
}

// sendTokenError writes an RFC 6749 JSON error response with HTTP 400 Bad Request status.
func (this *OAuth2AuthorizationServerFilter) sendTokenError(handler SecurityHandler, errCode, errDesc string) error {
	handler.SetHeader("Content-Type", "application/json")
	resp := map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	}
	Try(func() {
		bytes := RaiseVal(json.Marshal(resp))
		_, writeErr := handler.Write(bytes)
		RaiseNilErr(writeErr)
	}).LogError()
	return handler.Error(http.StatusBadRequest, errDesc)
}
