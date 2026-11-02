package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2AuthorizeRequest encapsulates parameters to authorize or re-authorize a client
type OAuth2AuthorizeRequest struct {
	ClientRegistrationID string
	ClientRegistration   *ClientRegistration
	PrincipalName        string
	AuthorizedClient     *OAuth2AuthorizedClient
	Scopes               []string
}

// OAuth2AuthorizedClientProvider handles authorization for a specific grant or state
type OAuth2AuthorizedClientProvider interface {
	Authorize(request *OAuth2AuthorizeRequest) (*OAuth2AuthorizedClient, Error)
	Supports(request *OAuth2AuthorizeRequest) bool
}

// OAuth2AuthorizedClientManager orchestrates client authorization
type OAuth2AuthorizedClientManager interface {
	Authorize(request *OAuth2AuthorizeRequest) (*OAuth2AuthorizedClient, Error)
}

// DefaultOAuth2AuthorizedClientManager is the default implementation of OAuth2AuthorizedClientManager
type DefaultOAuth2AuthorizedClientManager struct {
	clientRegistrationRepo ClientRegistrationRepository
	authorizedClientRepo   OAuth2AuthorizedClientService
	providers              []OAuth2AuthorizedClientProvider
}

func (this DefaultOAuth2AuthorizedClientManager) New(
	clientRepo ClientRegistrationRepository,
	clientService OAuth2AuthorizedClientService,
	providers ...OAuth2AuthorizedClientProvider,
) *DefaultOAuth2AuthorizedClientManager {
	if len(providers) == 0 {
		providers = []OAuth2AuthorizedClientProvider{
			RefreshTokenAuthorizedClientProvider{}.New(nil),
			ClientCredentialsAuthorizedClientProvider{}.New(nil),
		}
	}
	this.clientRegistrationRepo = clientRepo
	this.authorizedClientRepo = clientService
	this.providers = providers
	return &this
}

func NewDefaultOAuth2AuthorizedClientManager(
	clientRepo ClientRegistrationRepository,
	clientService OAuth2AuthorizedClientService,
	providers ...OAuth2AuthorizedClientProvider,
) *DefaultOAuth2AuthorizedClientManager {
	return DefaultOAuth2AuthorizedClientManager{}.New(clientRepo, clientService, providers...)
}

func (this *DefaultOAuth2AuthorizedClientManager) Authorize(request *OAuth2AuthorizeRequest) (*OAuth2AuthorizedClient, Error) {
	if request.ClientRegistration == nil {
		if request.ClientRegistrationID == "" {
			return nil, NewError("InvalidRequestError", "client registration or registration ID is required")
		}
		if this.clientRegistrationRepo == nil {
			return nil, NewError("ConfigurationError", "client registration repository is not configured")
		}
		reg, err := this.clientRegistrationRepo.FindByRegistrationID(request.ClientRegistrationID)
		if err != nil {
			return nil, err
		}
		request.ClientRegistration = reg
	}

	if request.AuthorizedClient == nil && this.authorizedClientRepo != nil {
		client, err := this.authorizedClientRepo.LoadAuthorizedClient(request.ClientRegistration.RegistrationID, request.PrincipalName)
		if err != nil {
			err.LogError()
		}
		request.AuthorizedClient = client
	}

	if request.AuthorizedClient != nil && request.AuthorizedClient.AccessToken != nil {
		token := request.AuthorizedClient.AccessToken
		if token.ExpiresAt.IsZero() || !time.Now().Add(60*time.Second).After(token.ExpiresAt) {
			return request.AuthorizedClient, nil
		}
	}

	for _, provider := range this.providers {
		if provider.Supports(request) {
			authorizedClient, err := provider.Authorize(request)
			if err != nil {
				return nil, err
			}
			if authorizedClient != nil && this.authorizedClientRepo != nil {
				if err := this.authorizedClientRepo.SaveAuthorizedClient(authorizedClient); err != nil {
					err.LogError()
				}
			}
			return authorizedClient, nil
		}
	}

	return nil, NewError("UnsupportedRequestError", "no authorized client provider supported the request")
}

// RefreshTokenAuthorizedClientProvider refreshes expired access tokens
type RefreshTokenAuthorizedClientProvider struct {
	httpClient *http.Client
	clockSkew  time.Duration
}

func (this RefreshTokenAuthorizedClientProvider) New(client *http.Client) *RefreshTokenAuthorizedClientProvider {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	this.httpClient = client
	this.clockSkew = 60 * time.Second
	return &this
}

func NewRefreshTokenAuthorizedClientProvider(client *http.Client) *RefreshTokenAuthorizedClientProvider {
	return RefreshTokenAuthorizedClientProvider{}.New(client)
}

func (this *RefreshTokenAuthorizedClientProvider) Supports(request *OAuth2AuthorizeRequest) bool {
	if request.AuthorizedClient == nil || request.AuthorizedClient.RefreshToken == nil {
		return false
	}
	// Check if access token is expired or close to expiry
	token := request.AuthorizedClient.AccessToken
	if token == nil {
		return true
	}
	if !token.ExpiresAt.IsZero() && time.Now().Add(this.clockSkew).After(token.ExpiresAt) {
		return true
	}
	return false
}

func (this *RefreshTokenAuthorizedClientProvider) Authorize(request *OAuth2AuthorizeRequest) (*OAuth2AuthorizedClient, Error) {
	reg := request.ClientRegistration
	refreshToken := request.AuthorizedClient.RefreshToken

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeRefreshToken))
	data.Set("refresh_token", refreshToken.TokenValue)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, reg.ProviderDetails.TokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, NewErrorFrom(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(reg.ClientID, reg.ClientSecret)

	resp, reqErr := this.httpClient.Do(req)
	if reqErr != nil {
		return nil, NewError("TokenRefreshError", fmt.Sprintf("token refresh request failed: %s", reqErr))
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
		return nil, NewError("TokenRefreshError", fmt.Sprintf("token refresh returned status %d: %s", resp.StatusCode, string(body)))
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Scope        string `json:"scope,omitempty"`
		ExpiresIn    int64  `json:"expires_in"`
	}

	if jsonErr := json.NewDecoder(resp.Body).Decode(&tokenResp); jsonErr != nil {
		return nil, NewError("TokenRefreshDecodeError", fmt.Sprintf("failed to decode token refresh response: %s", jsonErr))
	}

	now := time.Now()
	var expiresAt time.Time
	if tokenResp.ExpiresIn > 0 {
		expiresAt = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	var scopes []string
	if tokenResp.Scope != "" {
		scopes = strings.Split(tokenResp.Scope, " ")
	}

	newAccessToken := OAuth2AccessToken{}.New(
		TokenType(tokenResp.TokenType),
		tokenResp.AccessToken,
		now,
		expiresAt,
		scopes,
	)

	newRefreshToken := refreshToken
	if tokenResp.RefreshToken != "" {
		newRefreshToken = OAuth2RefreshToken{}.New(tokenResp.RefreshToken, now, time.Time{})
	}

	return OAuth2AuthorizedClient{}.New(reg, request.PrincipalName, newAccessToken, newRefreshToken), nil
}

// ClientCredentialsAuthorizedClientProvider executes client credentials grant
type ClientCredentialsAuthorizedClientProvider struct {
	httpClient *http.Client
}

func (this ClientCredentialsAuthorizedClientProvider) New(client *http.Client) *ClientCredentialsAuthorizedClientProvider {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	this.httpClient = client
	return &this
}

func NewClientCredentialsAuthorizedClientProvider(client *http.Client) *ClientCredentialsAuthorizedClientProvider {
	return ClientCredentialsAuthorizedClientProvider{}.New(client)
}

func (this *ClientCredentialsAuthorizedClientProvider) Supports(request *OAuth2AuthorizeRequest) bool {
	if request.ClientRegistration == nil {
		return false
	}
	return request.ClientRegistration.AuthorizationGrantType == GrantTypeClientCredentials
}

func (this *ClientCredentialsAuthorizedClientProvider) Authorize(request *OAuth2AuthorizeRequest) (*OAuth2AuthorizedClient, Error) {
	reg := request.ClientRegistration

	data := url.Values{}
	data.Set("grant_type", string(GrantTypeClientCredentials))
	if len(reg.Scopes) > 0 {
		data.Set("scope", strings.Join(reg.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, reg.ProviderDetails.TokenURI, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, NewErrorFrom(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(reg.ClientID, reg.ClientSecret)

	resp, reqErr := this.httpClient.Do(req)
	if reqErr != nil {
		return nil, NewError("ClientCredentialsError", fmt.Sprintf("client_credentials request failed: %s", reqErr))
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
		return nil, NewError("ClientCredentialsError", fmt.Sprintf("client_credentials returned status %d: %s", resp.StatusCode, string(body)))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope,omitempty"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if jsonErr := json.NewDecoder(resp.Body).Decode(&tokenResp); jsonErr != nil {
		return nil, NewError("ClientCredentialsDecodeError", fmt.Sprintf("failed to decode client_credentials response: %s", jsonErr))
	}

	now := time.Now()
	var expiresAt time.Time
	if tokenResp.ExpiresIn > 0 {
		expiresAt = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	scopes := reg.Scopes
	if tokenResp.Scope != "" {
		scopes = strings.Split(tokenResp.Scope, " ")
	}

	newAccessToken := OAuth2AccessToken{}.New(
		TokenType(tokenResp.TokenType),
		tokenResp.AccessToken,
		now,
		expiresAt,
		scopes,
	)

	return OAuth2AuthorizedClient{}.New(reg, request.PrincipalName, newAccessToken, nil), nil
}
