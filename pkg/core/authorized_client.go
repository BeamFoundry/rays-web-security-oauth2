package core

// OAuth2AuthorizedClient represents an authorized client associated with a principal
type OAuth2AuthorizedClient struct {
	ClientRegistration *ClientRegistration `json:"client_registration"`
	AccessToken        *OAuth2AccessToken  `json:"access_token"`
	RefreshToken       *OAuth2RefreshToken `json:"refresh_token,omitempty"`
	PrincipalName      string              `json:"principal_name"`
}

// New creates a new OAuth2AuthorizedClient associating a client registration, principal, and tokens.
func (this OAuth2AuthorizedClient) New(
	registration *ClientRegistration,
	principalName string,
	accessToken *OAuth2AccessToken,
	refreshToken *OAuth2RefreshToken,
) *OAuth2AuthorizedClient {
	this.ClientRegistration = registration
	this.PrincipalName = principalName
	this.AccessToken = accessToken
	this.RefreshToken = refreshToken
	return &this
}

// NewOAuth2AuthorizedClient creates a new OAuth2AuthorizedClient.
func NewOAuth2AuthorizedClient(
	registration *ClientRegistration,
	principalName string,
	accessToken *OAuth2AccessToken,
	refreshToken *OAuth2RefreshToken,
) *OAuth2AuthorizedClient {
	return OAuth2AuthorizedClient{}.New(registration, principalName, accessToken, refreshToken)
}
