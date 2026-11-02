package login

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2LoginAuthenticationProvider validates authorization code tokens and loads user identity
type OAuth2LoginAuthenticationProvider struct {
	Component
	userService             OAuth2UserService
	oidcUserService         OidcUserService
	jwtDecoder              JwtDecoder
	httpClient              *http.Client
	injectedUserService     Optional[OAuth2UserService] `@:"Inject"`
	injectedOidcUserService Optional[OidcUserService]   `@:"Inject"`
	injectedJwtDecoder      Optional[JwtDecoder]        `@:"Inject"`
}

var (
	_, _                        = any(&OAuth2LoginAuthenticationProvider{}).(Stereotype)
	_    AuthenticationProvider = &OAuth2LoginAuthenticationProvider{}
	_    BeamPostConstruct      = &OAuth2LoginAuthenticationProvider{}
)

func (this OAuth2LoginAuthenticationProvider) New(
	client *http.Client,
	userService OAuth2UserService,
	oidcUserService OidcUserService,
) *OAuth2LoginAuthenticationProvider {
	if client == nil {
		client = http.DefaultClient
	}
	if userService == nil {
		userService = DefaultOAuth2UserService{}.New(client)
	}
	if oidcUserService == nil {
		oidcUserService = DefaultOidcUserService{}.New(userService)
	}
	this.httpClient = client
	this.userService = userService
	this.oidcUserService = oidcUserService
	return &this
}

func NewOAuth2LoginAuthenticationProvider(
	client *http.Client,
	userService OAuth2UserService,
	oidcUserService OidcUserService,
) *OAuth2LoginAuthenticationProvider {
	return OAuth2LoginAuthenticationProvider{}.New(client, userService, oidcUserService)
}

func (this *OAuth2LoginAuthenticationProvider) WithJwtDecoder(decoder JwtDecoder) *OAuth2LoginAuthenticationProvider {
	this.jwtDecoder = decoder
	return this
}

func (this *OAuth2LoginAuthenticationProvider) PostConstruct() Error {
	if this.httpClient == nil {
		this.httpClient = http.DefaultClient
	}
	if svc, ok := this.injectedUserService.Get(); ok {
		this.userService = svc
	} else if this.userService == nil {
		this.userService = DefaultOAuth2UserService{}.New(this.httpClient)
	}
	if oidc, ok := this.injectedOidcUserService.Get(); ok {
		this.oidcUserService = oidc
	} else if this.oidcUserService == nil {
		this.oidcUserService = DefaultOidcUserService{}.New(this.userService)
	}
	if dec, ok := this.injectedJwtDecoder.Get(); ok {
		this.jwtDecoder = dec
	}
	return nil
}

func (this *OAuth2LoginAuthenticationProvider) Supports(auth Authentication) bool {
	_, ok := auth.(*OAuth2LoginAuthenticationToken)
	return ok
}

func (this *OAuth2LoginAuthenticationProvider) Authenticate(auth Authentication) (Authentication, AuthenticationException) {
	loginToken, ok := auth.(*OAuth2LoginAuthenticationToken)
	if !ok {
		return auth, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorInvalidRequest, ErrorDescription: "token is not OAuth2LoginAuthenticationToken"},
			auth,
		)
	}

	if this.userService == nil {
		if svc, ok := this.injectedUserService.Get(); ok {
			this.userService = svc
		} else {
			if this.httpClient == nil {
				this.httpClient = http.DefaultClient
			}
			this.userService = DefaultOAuth2UserService{}.New(this.httpClient)
		}
	}
	if this.oidcUserService == nil {
		if oidc, ok := this.injectedOidcUserService.Get(); ok {
			this.oidcUserService = oidc
		} else {
			this.oidcUserService = DefaultOidcUserService{}.New(this.userService)
		}
	}

	reg := loginToken.ClientRegistration
	exchange := loginToken.AuthorizationExchange

	// Check if IdP reported an error in authorization response
	if exchange.AuthorizationResponse.Error != "" {
		oauthErr := OAuth2Error{
			ErrorCode:        exchange.AuthorizationResponse.Error,
			ErrorDescription: exchange.AuthorizationResponse.ErrorDesc,
		}
		return nil, OAuth2AuthenticationException{}.New(oauthErr, loginToken)
	}

	// 1. Exchange authorization code for tokens via Token Endpoint
	tokenResp, err := this.exchangeCodeForTokens(reg, exchange)
	if err != nil {
		oauthErr := OAuth2Error{
			ErrorCode:        OAuth2ErrorInvalidGrant,
			ErrorDescription: fmt.Sprintf("failed to exchange authorization code for tokens: %v", err),
		}
		return nil, OAuth2AuthenticationException{}.New(oauthErr, loginToken)
	}

	now := time.Now()
	var expiresAt time.Time
	if tokenResp.ExpiresIn > 0 {
		expiresAt = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	var scopes []string
	if tokenResp.Scope != "" {
		scopes = strings.Split(tokenResp.Scope, " ")
	} else {
		scopes = reg.Scopes
	}

	accessToken := OAuth2AccessToken{}.New(
		TokenType(tokenResp.TokenType),
		tokenResp.AccessToken,
		now,
		expiresAt,
		scopes,
	)

	// 2. Load User Details (OIDC vs standard OAuth2)
	isOidc := slices.Contains(scopes, "openid") || slices.Contains(reg.Scopes, "openid") || tokenResp.IdToken != ""

	var authenticatedUser OAuth2User
	if isOidc {
		var idToken *OidcIdToken
		if tokenResp.IdToken != "" {
			decoder := this.jwtDecoder
			if decoder == nil && reg.ProviderDetails.JwkSetURI != "" {
				jwxDec := NewJwxJwtDecoderWithRemoteJWKS(reg.ProviderDetails.JwkSetURI)
				if reg.ProviderDetails.IssuerURI != "" {
					jwxDec = jwxDec.WithIssuer(reg.ProviderDetails.IssuerURI)
				}
				if reg.ClientID != "" {
					jwxDec = jwxDec.WithAudience(reg.ClientID)
				}
				decoder = jwxDec
			}

			if decoder == nil {
				oauthErr := OAuth2Error{
					ErrorCode:        OAuth2ErrorServerError,
					ErrorDescription: "missing jwt decoder or jwk_set_uri for id_token verification",
				}
				return nil, OAuth2AuthenticationException{}.New(oauthErr, loginToken)
			}

			decoded, decodeErr := decoder.Decode(tokenResp.IdToken)
			if decodeErr != nil {
				decodeErr.LogError()
				oauthErr := OAuth2Error{
					ErrorCode:        OAuth2ErrorInvalidGrant,
					ErrorDescription: fmt.Sprintf("invalid id_token: %v", decodeErr),
				}
				return nil, OAuth2AuthenticationException{}.New(oauthErr, loginToken)
			}

			idToken = &OidcIdToken{
				TokenValue: tokenResp.IdToken,
				Claims:     decoded.Claims,
			}
		}

		oidcRequest := &OidcUserRequest{
			ClientRegistration: reg,
			AccessToken:        accessToken,
			IdToken:            idToken,
		}

		user, userErr := this.oidcUserService.LoadUser(oidcRequest)
		if userErr != nil {
			oauthErr := OAuth2Error{
				ErrorCode:        OAuth2ErrorServerError,
				ErrorDescription: fmt.Sprintf("failed to load oidc user: %v", userErr),
			}
			return nil, OAuth2AuthenticationException{}.New(oauthErr, loginToken)
		}
		authenticatedUser = user
	} else {
		userRequest := &OAuth2UserRequest{
			ClientRegistration: reg,
			AccessToken:        accessToken,
		}

		user, userErr := this.userService.LoadUser(userRequest)
		if userErr != nil {
			oauthErr := OAuth2Error{
				ErrorCode:        OAuth2ErrorServerError,
				ErrorDescription: fmt.Sprintf("failed to load oauth2 user: %v", userErr),
			}
			return nil, OAuth2AuthenticationException{}.New(oauthErr, loginToken)
		}
		authenticatedUser = user
	}

	// 3. Construct authenticated token
	result := OAuth2AuthenticationToken{}.New(
		authenticatedUser,
		authenticatedUser.GetAuthorities(),
		reg.RegistrationID,
	)

	return result, nil
}

type tokenEndpointResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"`
}

func (this *OAuth2LoginAuthenticationProvider) exchangeCodeForTokens(
	reg *ClientRegistration,
	exchange OAuth2AuthorizationExchange,
) (*tokenEndpointResponse, Error) {
	data := url.Values{}
	data.Set("grant_type", string(GrantTypeAuthorizationCode))
	data.Set("code", exchange.AuthorizationResponse.Code)
	data.Set("redirect_uri", exchange.AuthorizationRequest.RedirectURI)
	if exchange.AuthorizationRequest.CodeVerifier != "" {
		data.Set("code_verifier", exchange.AuthorizationRequest.CodeVerifier)
	}

	if reg.ClientAuthenticationMethod == ClientAuthMethodPost {
		data.Set("client_id", reg.ClientID)
		data.Set("client_secret", reg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, reg.ProviderDetails.TokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, NewErrorFrom(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if reg.ClientAuthenticationMethod != ClientAuthMethodPost {
		req.SetBasicAuth(reg.ClientID, reg.ClientSecret)
	}

	resp, reqErr := this.httpClient.Do(req)
	if reqErr != nil {
		return nil, NewError("TokenExchangeError", fmt.Sprintf("token request failed: %s", reqErr))
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			NewErrorFrom(closeErr).LogError()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			NewErrorFrom(readErr).LogError()
		}
		return nil, NewError("TokenExchangeStatusError", fmt.Sprintf("token exchange failed (status %d): %s", resp.StatusCode, string(body)))
	}

	var tokenResp tokenEndpointResponse
	if jsonErr := json.NewDecoder(resp.Body).Decode(&tokenResp); jsonErr != nil {
		return nil, NewError("TokenExchangeDecodeError", fmt.Sprintf("failed to decode token response: %s", jsonErr))
	}

	return &tokenResp, nil
}
