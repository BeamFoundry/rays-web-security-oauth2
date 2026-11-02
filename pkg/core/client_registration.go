package core

// AuthorizationGrantType represents the OAuth2 grant type
type AuthorizationGrantType string

const (
	GrantTypeAuthorizationCode AuthorizationGrantType = "authorization_code"
	GrantTypeClientCredentials AuthorizationGrantType = "client_credentials"
	GrantTypeRefreshToken      AuthorizationGrantType = "refresh_token"
	GrantTypePassword          AuthorizationGrantType = "password" // legacy RFC 6749
)

// ClientAuthenticationMethod represents the method used to authenticate a client
type ClientAuthenticationMethod string

const (
	ClientAuthMethodBasic  ClientAuthenticationMethod = "client_secret_basic"
	ClientAuthMethodPost   ClientAuthenticationMethod = "client_secret_post"
	ClientAuthMethodNone   ClientAuthenticationMethod = "none" // PKCE public client
	ClientAuthMethodSecret ClientAuthenticationMethod = "client_secret_jwt"
	ClientAuthMethodKey    ClientAuthenticationMethod = "private_key_jwt"
)

// ProviderDetails holds endpoints and configuration for an external OAuth2/OIDC provider
type ProviderDetails struct {
	AuthorizationURI      string `json:"authorization_uri"`
	TokenURI              string `json:"token_uri"`
	UserInfoURI           string `json:"user_info_uri"`
	JwkSetURI             string `json:"jwk_set_uri"`
	IssuerURI             string `json:"issuer_uri"`
	UserNameAttributeName string `json:"user_name_attribute_name"`
}

// ClientRegistration represents a registered OAuth 2.0 / OpenID Connect client
type ClientRegistration struct {
	ProviderDetails            ProviderDetails            `json:"provider_details"`
	RegistrationID             string                     `json:"registration_id"`
	ClientID                   string                     `json:"client_id"`
	ClientSecret               string                     `json:"client_secret"`
	ClientAuthenticationMethod ClientAuthenticationMethod `json:"client_authentication_method"`
	AuthorizationGrantType     AuthorizationGrantType     `json:"authorization_grant_type"`
	RedirectURI                string                     `json:"redirect_uri"`
	ClientName                 string                     `json:"client_name"`
	Scopes                     []string                   `json:"scopes"`
}

// ClientRegistrationBuilder provides a fluent builder for ClientRegistration
type ClientRegistrationBuilder struct {
	reg ClientRegistration
}

func (this ClientRegistrationBuilder) New(registrationID string) *ClientRegistrationBuilder {
	this.reg = ClientRegistration{
		RegistrationID:             registrationID,
		ClientAuthenticationMethod: ClientAuthMethodBasic,
		AuthorizationGrantType:     GrantTypeAuthorizationCode,
		Scopes:                     make([]string, 0),
	}
	return &this
}

func NewClientRegistration(registrationID string) *ClientRegistrationBuilder {
	return ClientRegistrationBuilder{}.New(registrationID)
}

func (this *ClientRegistrationBuilder) ClientID(clientID string) *ClientRegistrationBuilder {
	this.reg.ClientID = clientID
	return this
}

func (this *ClientRegistrationBuilder) ClientSecret(secret string) *ClientRegistrationBuilder {
	this.reg.ClientSecret = secret
	return this
}

func (this *ClientRegistrationBuilder) ClientAuthenticationMethod(method ClientAuthenticationMethod) *ClientRegistrationBuilder {
	this.reg.ClientAuthenticationMethod = method
	return this
}

func (this *ClientRegistrationBuilder) AuthorizationGrantType(grantType AuthorizationGrantType) *ClientRegistrationBuilder {
	this.reg.AuthorizationGrantType = grantType
	return this
}

func (this *ClientRegistrationBuilder) RedirectURI(uri string) *ClientRegistrationBuilder {
	this.reg.RedirectURI = uri
	return this
}

func (this *ClientRegistrationBuilder) Scope(scopes ...string) *ClientRegistrationBuilder {
	this.reg.Scopes = append(this.reg.Scopes, scopes...)
	return this
}

func (this *ClientRegistrationBuilder) ClientName(name string) *ClientRegistrationBuilder {
	this.reg.ClientName = name
	return this
}

func (this *ClientRegistrationBuilder) AuthorizationURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.AuthorizationURI = uri
	return this
}

func (this *ClientRegistrationBuilder) TokenURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.TokenURI = uri
	return this
}

func (this *ClientRegistrationBuilder) UserInfoURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.UserInfoURI = uri
	return this
}

func (this *ClientRegistrationBuilder) JwkSetURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.JwkSetURI = uri
	return this
}

func (this *ClientRegistrationBuilder) IssuerURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.IssuerURI = uri
	return this
}

func (this *ClientRegistrationBuilder) UserNameAttributeName(name string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.UserNameAttributeName = name
	return this
}

func (this *ClientRegistrationBuilder) Build() *ClientRegistration {
	res := this.reg
	return &res
}
