package core

// AuthorizationGrantType represents the OAuth2 grant type
type AuthorizationGrantType string

const (
	// GrantTypeAuthorizationCode represents the OAuth 2.0 Authorization Code grant type.
	GrantTypeAuthorizationCode AuthorizationGrantType = "authorization_code"
	// GrantTypeClientCredentials represents the OAuth 2.0 Client Credentials grant type.
	GrantTypeClientCredentials AuthorizationGrantType = "client_credentials"
	// GrantTypeRefreshToken represents the OAuth 2.0 Refresh Token grant type.
	GrantTypeRefreshToken AuthorizationGrantType = "refresh_token"
	// GrantTypePassword represents the Resource Owner Password Credentials grant type.
	GrantTypePassword AuthorizationGrantType = "password" // legacy RFC 6749
)

// ClientAuthenticationMethod represents the method used to authenticate a client
type ClientAuthenticationMethod string

const (
	// ClientAuthMethodBasic authenticates the client using HTTP Basic authentication.
	ClientAuthMethodBasic ClientAuthenticationMethod = "client_secret_basic"
	// ClientAuthMethodPost authenticates the client by including credentials in the HTTP POST request body.
	ClientAuthMethodPost ClientAuthenticationMethod = "client_secret_post"
	// ClientAuthMethodNone represents the "none" authentication method for public clients without a client secret.
	// Note: built-in authorization-code, refresh-token, and client-credentials token exchanges use HTTP Basic authentication for this method rather than implementing public-client (unauthenticated) protocol authentication behavior.
	ClientAuthMethodNone ClientAuthenticationMethod = "none" // PKCE public client
	// ClientAuthMethodSecret represents the "client_secret_jwt" authentication method (JWT assertion signed with a shared client secret).
	// Note: built-in authorization-code, refresh-token, and client-credentials token exchanges use HTTP Basic authentication for this method rather than implementing "client_secret_jwt" protocol authentication behavior.
	ClientAuthMethodSecret ClientAuthenticationMethod = "client_secret_jwt"
	// ClientAuthMethodKey represents the "private_key_jwt" authentication method (JWT assertion signed with an asymmetric private key).
	// Note: built-in authorization-code, refresh-token, and client-credentials token exchanges use HTTP Basic authentication for this method rather than implementing "private_key_jwt" protocol authentication behavior.
	ClientAuthMethodKey ClientAuthenticationMethod = "private_key_jwt"
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

// New initializes a new ClientRegistrationBuilder with the specified registration ID and sensible defaults.
func (this ClientRegistrationBuilder) New(registrationID string) *ClientRegistrationBuilder {
	this.reg = ClientRegistration{
		RegistrationID:             registrationID,
		ClientAuthenticationMethod: ClientAuthMethodBasic,
		AuthorizationGrantType:     GrantTypeAuthorizationCode,
		Scopes:                     make([]string, 0),
	}
	return &this
}

// NewClientRegistration creates a new ClientRegistrationBuilder for the specified registration ID.
func NewClientRegistration(registrationID string) *ClientRegistrationBuilder {
	return ClientRegistrationBuilder{}.New(registrationID)
}

// ClientID sets the OAuth 2.0 client identifier.
func (this *ClientRegistrationBuilder) ClientID(clientID string) *ClientRegistrationBuilder {
	this.reg.ClientID = clientID
	return this
}

// ClientSecret sets the OAuth 2.0 client secret.
func (this *ClientRegistrationBuilder) ClientSecret(secret string) *ClientRegistrationBuilder {
	this.reg.ClientSecret = secret
	return this
}

// ClientAuthenticationMethod sets the method used to authenticate the client with the authorization server.
func (this *ClientRegistrationBuilder) ClientAuthenticationMethod(method ClientAuthenticationMethod) *ClientRegistrationBuilder {
	this.reg.ClientAuthenticationMethod = method
	return this
}

// AuthorizationGrantType sets the OAuth 2.0 authorization grant type for the client.
func (this *ClientRegistrationBuilder) AuthorizationGrantType(grantType AuthorizationGrantType) *ClientRegistrationBuilder {
	this.reg.AuthorizationGrantType = grantType
	return this
}

// RedirectURI sets the registered redirection URI for authorization callbacks.
func (this *ClientRegistrationBuilder) RedirectURI(uri string) *ClientRegistrationBuilder {
	this.reg.RedirectURI = uri
	return this
}

// Scope appends one or more scopes to the client registration.
func (this *ClientRegistrationBuilder) Scope(scopes ...string) *ClientRegistrationBuilder {
	this.reg.Scopes = append(this.reg.Scopes, scopes...)
	return this
}

// ClientName sets the human-readable display name of the client.
func (this *ClientRegistrationBuilder) ClientName(name string) *ClientRegistrationBuilder {
	this.reg.ClientName = name
	return this
}

// AuthorizationURI sets the provider's OAuth 2.0 authorization endpoint URI.
func (this *ClientRegistrationBuilder) AuthorizationURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.AuthorizationURI = uri
	return this
}

// TokenURI sets the provider's OAuth 2.0 token endpoint URI.
func (this *ClientRegistrationBuilder) TokenURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.TokenURI = uri
	return this
}

// UserInfoURI sets the provider's OpenID Connect UserInfo endpoint URI.
func (this *ClientRegistrationBuilder) UserInfoURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.UserInfoURI = uri
	return this
}

// JwkSetURI sets the provider's JSON Web Key Set (JWKS) endpoint URI.
func (this *ClientRegistrationBuilder) JwkSetURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.JwkSetURI = uri
	return this
}

// IssuerURI sets the provider's issuer identifier URI.
func (this *ClientRegistrationBuilder) IssuerURI(uri string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.IssuerURI = uri
	return this
}

// UserNameAttributeName sets the claim or attribute name used to extract the principal's username.
func (this *ClientRegistrationBuilder) UserNameAttributeName(name string) *ClientRegistrationBuilder {
	this.reg.ProviderDetails.UserNameAttributeName = name
	return this
}

// Build constructs and returns the configured ClientRegistration instance.
func (this *ClientRegistrationBuilder) Build() *ClientRegistration {
	res := this.reg
	return &res
}
