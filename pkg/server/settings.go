package server

// AuthorizationServerSettings holds the URIs and configuration for the Authorization Server
type AuthorizationServerSettings struct {
	Issuer                     string `json:"issuer"`
	AuthorizationEndpoint      string `json:"authorization_endpoint"`
	TokenEndpoint              string `json:"token_endpoint"`
	JwkSetEndpoint             string `json:"jwk_set_endpoint"`
	TokenRevocationEndpoint    string `json:"token_revocation_endpoint"`
	TokenIntrospectionEndpoint string `json:"token_introspection_endpoint"`
	OidcDiscoveryEndpoint      string `json:"oidc_discovery_endpoint"`
	UserInfoEndpoint           string `json:"user_info_endpoint"`
}

func (this AuthorizationServerSettings) New(issuer string) *AuthorizationServerSettings {
	this.Issuer = issuer
	this.AuthorizationEndpoint = "/oauth2/authorize"
	this.TokenEndpoint = "/oauth2/token"
	this.JwkSetEndpoint = "/oauth2/jwks"
	this.TokenRevocationEndpoint = "/oauth2/revoke"
	this.TokenIntrospectionEndpoint = "/oauth2/introspect"
	this.OidcDiscoveryEndpoint = "/.well-known/openid-configuration"
	this.UserInfoEndpoint = "/userinfo"
	return &this
}

func (this AuthorizationServerSettings) NewDefault(issuer string) *AuthorizationServerSettings {
	return this.New(issuer)
}

func NewDefaultAuthorizationServerSettings(issuer string) *AuthorizationServerSettings {
	return AuthorizationServerSettings{}.NewDefault(issuer)
}
