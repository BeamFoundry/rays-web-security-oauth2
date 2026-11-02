package login

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2UserRequest contains the context to load user attributes
type OAuth2UserRequest struct {
	ClientRegistration *ClientRegistration
	AccessToken        *OAuth2AccessToken
	AdditionalParams   map[string]any
}

// OAuth2UserService loads user attributes from an OAuth2 provider UserInfo endpoint
const subClaimName = "sub"

type OAuth2UserService interface {
	LoadUser(userRequest *OAuth2UserRequest) (OAuth2User, Error)
}

// DefaultOAuth2UserService is the default implementation of OAuth2UserService
type DefaultOAuth2UserService struct {
	httpClient *http.Client
}

func (this DefaultOAuth2UserService) New(client *http.Client) *DefaultOAuth2UserService {
	if client == nil {
		client = http.DefaultClient
	}
	this.httpClient = client
	return &this
}

func NewDefaultOAuth2UserService(client *http.Client) *DefaultOAuth2UserService {
	return DefaultOAuth2UserService{}.New(client)
}

func (this *DefaultOAuth2UserService) LoadUser(userRequest *OAuth2UserRequest) (OAuth2User, Error) {
	userInfoURI := userRequest.ClientRegistration.ProviderDetails.UserInfoURI
	if userInfoURI == "" {
		// If no user info endpoint is defined, fallback to access token attributes
		attrs := map[string]any{
			subClaimName: userRequest.ClientRegistration.ClientID,
		}
		authorities := []GrantedAuthority{Authority("ROLE_USER")}
		return DefaultOAuth2User{}.New(authorities, attrs, subClaimName), nil
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, userInfoURI, http.NoBody)
	if err != nil {
		return nil, NewErrorFrom(err)
	}
	req.Header.Set("Authorization", "Bearer "+userRequest.AccessToken.TokenValue)
	req.Header.Set("Accept", "application/json")

	resp, reqErr := this.httpClient.Do(req)
	if reqErr != nil {
		return nil, NewError("UserInfoRequestError", fmt.Sprintf("userinfo request failed: %s", reqErr))
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			NewErrorFrom(closeErr).LogError()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, NewError("UserInfoStatusError", fmt.Sprintf("userinfo request returned status %d", resp.StatusCode))
	}

	var attrs map[string]any
	if jsonErr := json.NewDecoder(resp.Body).Decode(&attrs); jsonErr != nil {
		return nil, NewError("UserInfoDecodeError", fmt.Sprintf("failed to parse userinfo json: %s", jsonErr))
	}

	nameKey := userRequest.ClientRegistration.ProviderDetails.UserNameAttributeName
	if nameKey == "" {
		nameKey = subClaimName
		if _, ok := attrs[subClaimName]; !ok {
			if _, ok := attrs["id"]; ok {
				nameKey = "id"
			} else if _, ok := attrs["login"]; ok {
				nameKey = "login"
			}
		}
	}

	authorities := []GrantedAuthority{Authority("ROLE_USER")}
	for _, scope := range userRequest.AccessToken.Scopes {
		authorities = append(authorities, Authority("SCOPE_"+scope))
	}

	return DefaultOAuth2User{}.New(authorities, attrs, nameKey), nil
}

// OidcUserRequest contains context to load an OIDC user
type OidcUserRequest struct {
	ClientRegistration *ClientRegistration
	AccessToken        *OAuth2AccessToken
	IdToken            *OidcIdToken
}

// OidcUserService loads user attributes for OpenID Connect users
type OidcUserService interface {
	LoadUser(userRequest *OidcUserRequest) (OidcUser, Error)
}

// DefaultOidcUserService is the default implementation of OidcUserService
type DefaultOidcUserService struct {
	oauth2UserService OAuth2UserService
}

func (this DefaultOidcUserService) New(oauth2UserService OAuth2UserService) *DefaultOidcUserService {
	if oauth2UserService == nil {
		oauth2UserService = DefaultOAuth2UserService{}.New(nil)
	}
	this.oauth2UserService = oauth2UserService
	return &this
}

func NewDefaultOidcUserService(oauth2UserService OAuth2UserService) *DefaultOidcUserService {
	return DefaultOidcUserService{}.New(oauth2UserService)
}

func (this *DefaultOidcUserService) LoadUser(userRequest *OidcUserRequest) (OidcUser, Error) {
	authorities := []GrantedAuthority{Authority("ROLE_USER")}
	for _, scope := range userRequest.AccessToken.Scopes {
		authorities = append(authorities, Authority("SCOPE_"+scope))
	}

	var userInfo *OidcUserInfo
	if userRequest.ClientRegistration.ProviderDetails.UserInfoURI != "" {
		oauth2Req := &OAuth2UserRequest{
			ClientRegistration: userRequest.ClientRegistration,
			AccessToken:        userRequest.AccessToken,
		}
		oauth2User, err := this.oauth2UserService.LoadUser(oauth2Req)
		if err == nil && oauth2User != nil {
			userInfo = &OidcUserInfo{Claims: oauth2User.GetAttributes()}
		} else if err != nil {
			err.LogError()
		}
	}

	nameKey := userRequest.ClientRegistration.ProviderDetails.UserNameAttributeName
	if nameKey == "" {
		nameKey = subClaimName
	}

	return DefaultOidcUser{}.New(authorities, userRequest.IdToken, userInfo, nameKey), nil
}
