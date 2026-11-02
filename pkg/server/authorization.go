package server

import (
	"sync"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OAuth2ParameterCode is the authorization code grant parameter name and token type
const OAuth2ParameterCode = "code"

// AuthorizationCode holds the issued authorization code details
type AuthorizationCode struct {
	Value               string    `json:"value"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	RedirectURI         string    `json:"redirect_uri"`
	Invalidated         bool      `json:"invalidated"`
}

// OAuth2Authorization represents an ongoing or completed OAuth 2.0 authorization
type OAuth2Authorization struct {
	AuthorizationCode  *AuthorizationCode  `json:"authorization_code,omitempty"`
	AccessToken        *OAuth2AccessToken  `json:"access_token,omitempty"`
	RefreshToken       *OAuth2RefreshToken `json:"refresh_token,omitempty"`
	ID                 string              `json:"id"`
	RegisteredClientID string              `json:"registered_client_id"`
	PrincipalName      string              `json:"principal_name"`
	AuthorizedScopes   []string            `json:"authorized_scopes"`
}

// OAuth2AuthorizationService manages authorization sessions
type OAuth2AuthorizationService interface {
	Save(authorization *OAuth2Authorization) Error
	Remove(authorization *OAuth2Authorization) Error
	FindByID(id string) (*OAuth2Authorization, Error)
	FindByToken(token, tokenType string) (*OAuth2Authorization, Error)
}

// InMemoryOAuth2AuthorizationService stores authorizations in memory
type InMemoryOAuth2AuthorizationService struct {
	mu             *sync.RWMutex
	byID           map[string]*OAuth2Authorization
	byAuthCode     map[string]*OAuth2Authorization
	byAccessToken  map[string]*OAuth2Authorization
	byRefreshToken map[string]*OAuth2Authorization
}

func (this InMemoryOAuth2AuthorizationService) New() *InMemoryOAuth2AuthorizationService {
	this.mu = &sync.RWMutex{}
	this.byID = make(map[string]*OAuth2Authorization)
	this.byAuthCode = make(map[string]*OAuth2Authorization)
	this.byAccessToken = make(map[string]*OAuth2Authorization)
	this.byRefreshToken = make(map[string]*OAuth2Authorization)
	return &this
}

func NewInMemoryOAuth2AuthorizationService() *InMemoryOAuth2AuthorizationService {
	return InMemoryOAuth2AuthorizationService{}.New()
}

func (this *InMemoryOAuth2AuthorizationService) Save(auth *OAuth2Authorization) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

	this.byID[auth.ID] = auth
	if auth.AuthorizationCode != nil && auth.AuthorizationCode.Value != "" {
		this.byAuthCode[auth.AuthorizationCode.Value] = auth
	}
	if auth.AccessToken != nil && auth.AccessToken.TokenValue != "" {
		this.byAccessToken[auth.AccessToken.TokenValue] = auth
	}
	if auth.RefreshToken != nil && auth.RefreshToken.TokenValue != "" {
		this.byRefreshToken[auth.RefreshToken.TokenValue] = auth
	}
	return nil
}

func (this *InMemoryOAuth2AuthorizationService) Remove(auth *OAuth2Authorization) Error {
	this.mu.Lock()
	defer this.mu.Unlock()

	delete(this.byID, auth.ID)
	if auth.AuthorizationCode != nil {
		delete(this.byAuthCode, auth.AuthorizationCode.Value)
	}
	if auth.AccessToken != nil {
		delete(this.byAccessToken, auth.AccessToken.TokenValue)
	}
	if auth.RefreshToken != nil {
		delete(this.byRefreshToken, auth.RefreshToken.TokenValue)
	}
	return nil
}

func (this *InMemoryOAuth2AuthorizationService) FindByID(id string) (*OAuth2Authorization, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	auth, ok := this.byID[id]
	if !ok {
		return nil, NewError("AuthorizationNotFound", "authorization not found by id: "+id)
	}
	return auth, nil
}

func (this *InMemoryOAuth2AuthorizationService) FindByToken(token, tokenType string) (*OAuth2Authorization, Error) {
	this.mu.RLock()
	defer this.mu.RUnlock()

	switch tokenType {
	case OAuth2ParameterCode:
		if auth, ok := this.byAuthCode[token]; ok {
			return auth, nil
		}
	case "access_token":
		if auth, ok := this.byAccessToken[token]; ok {
			return auth, nil
		}
	case "refresh_token":
		if auth, ok := this.byRefreshToken[token]; ok {
			return auth, nil
		}
	default:
	}
	return nil, NewError("AuthorizationNotFound", "authorization not found for token type "+tokenType)
}
