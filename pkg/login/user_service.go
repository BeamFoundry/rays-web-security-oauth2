package login

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

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

// subClaimName is the standard OpenID Connect subject identifier claim name.
const subClaimName = "sub"

// OAuth2UserService loads user attributes from an OAuth2 provider UserInfo endpoint
type OAuth2UserService interface {
	// LoadUser retrieves an authenticated OAuth2User from the provider's UserInfo endpoint.
	LoadUser(userRequest *OAuth2UserRequest) (OAuth2User, Error)
}

// DefaultOAuth2UserService is the default implementation of OAuth2UserService
type DefaultOAuth2UserService struct {
	httpClient *http.Client
}

// New creates a new DefaultOAuth2UserService using the provided HTTP client (or http.DefaultClient if nil).
func (this DefaultOAuth2UserService) New(client *http.Client) *DefaultOAuth2UserService {
	if client == nil {
		client = http.DefaultClient
	}
	this.httpClient = client
	return &this
}

// NewDefaultOAuth2UserService creates a new DefaultOAuth2UserService.
func NewDefaultOAuth2UserService(client *http.Client) *DefaultOAuth2UserService {
	return DefaultOAuth2UserService{}.New(client)
}

// LoadUser queries the provider's UserInfo endpoint with the access token and constructs a DefaultOAuth2User.
func (this *DefaultOAuth2UserService) LoadUser(userRequest *OAuth2UserRequest) (OAuth2User, Error) {
	userInfoURI := userRequest.ClientRegistration.ProviderDetails.UserInfoURI
	if userInfoURI == "" {
		return nil, NewError("InvalidConfigurationError", "userInfoURI is missing in client registration provider details")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURI, http.NoBody)
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
		Try(func() {
			RaiseNilErr(resp.Body.Close())
		}).LogError()
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
	// LoadUser constructs an authenticated OidcUser from the ID token and optional UserInfo endpoint.
	LoadUser(userRequest *OidcUserRequest) (OidcUser, Error)
}

// DefaultOidcUserService is the default implementation of OidcUserService
type DefaultOidcUserService struct {
	oauth2UserService OAuth2UserService
}

// New creates a new DefaultOidcUserService delegating UserInfo requests to the provided OAuth2UserService.
func (this DefaultOidcUserService) New(oauth2UserService OAuth2UserService) *DefaultOidcUserService {
	if oauth2UserService == nil {
		oauth2UserService = DefaultOAuth2UserService{}.New(nil)
	}
	this.oauth2UserService = oauth2UserService
	return &this
}

// NewDefaultOidcUserService creates a new DefaultOidcUserService.
func NewDefaultOidcUserService(oauth2UserService OAuth2UserService) *DefaultOidcUserService {
	return DefaultOidcUserService{}.New(oauth2UserService)
}

// LoadUser validates the ID token subject claim, optionally fetches UserInfo claims, and returns a DefaultOidcUser.
func (this *DefaultOidcUserService) LoadUser(userRequest *OidcUserRequest) (OidcUser, Error) {
	authorities := []GrantedAuthority{Authority("ROLE_USER")}
	for _, scope := range userRequest.AccessToken.Scopes {
		authorities = append(authorities, Authority("SCOPE_"+scope))
	}

	var idTokenSub string
	if userRequest.IdToken != nil && userRequest.IdToken.Claims != nil {
		if s, ok := userRequest.IdToken.Claims[subClaimName].(string); ok && s != "" {
			idTokenSub = s
		}
	}
	if idTokenSub == "" {
		return nil, NewError("InvalidUserError", fmt.Sprintf("id_token %q claim is missing or empty", subClaimName))
	}

	var userInfo *OidcUserInfo
	if userRequest.ClientRegistration.ProviderDetails.UserInfoURI != "" {
		oauth2Req := &OAuth2UserRequest{
			ClientRegistration: userRequest.ClientRegistration,
			AccessToken:        userRequest.AccessToken,
		}
		oauth2User, err := this.oauth2UserService.LoadUser(oauth2Req)
		if err == nil && oauth2User != nil {
			attrs := oauth2User.GetAttributes()
			var userInfoSub string
			if attrs != nil {
				if s, ok := attrs[subClaimName].(string); ok {
					userInfoSub = s
				}
			}
			if userInfoSub == "" || idTokenSub != userInfoSub {
				return nil, NewError("InvalidUserInfoResponse", fmt.Sprintf("userInfo sub %q does not match idToken sub %q", userInfoSub, idTokenSub))
			}
			userInfo = &OidcUserInfo{Claims: attrs}
		} else if err != nil {
			err.LogError()
		}
	}

	nameKey := userRequest.ClientRegistration.ProviderDetails.UserNameAttributeName
	if nameKey == "" {
		nameKey = subClaimName
	}

	user := DefaultOidcUser{}.New(authorities, userRequest.IdToken, userInfo, nameKey)
	if user.GetName() == "" {
		return nil, NewError("InvalidUserError", fmt.Sprintf("oidc user name attribute %q is missing or empty", nameKey))
	}

	return user, nil
}
