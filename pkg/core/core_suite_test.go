package core_test

import (
	"testing"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OAuth2 Core Suite")
}

var _ = Describe("ClientRegistrationBuilder", func() {
	It("can build a full client registration", func() {
		reg := ClientRegistrationBuilder{}.New("google").
			ClientID("google-client-id").
			ClientSecret("google-secret").
			ClientAuthenticationMethod(ClientAuthMethodBasic).
			AuthorizationGrantType(GrantTypeAuthorizationCode).
			RedirectURI("/login/oauth2/code/google").
			Scope("openid", "profile", "email").
			AuthorizationURI("https://accounts.google.com/o/oauth2/v2/auth").
			TokenURI("https://oauth2.googleapis.com/token").
			UserInfoURI("https://openidconnect.googleapis.com/v1/userinfo").
			JwkSetURI("https://www.googleapis.com/oauth2/v3/certs").
			UserNameAttributeName("sub").
			ClientName("Google").
			Build()

		Expect(reg.RegistrationID).To(Equal("google"))
		Expect(reg.ClientID).To(Equal("google-client-id"))
		Expect(reg.ClientSecret).To(Equal("google-secret"))
		Expect(reg.ClientAuthenticationMethod).To(Equal(ClientAuthMethodBasic))
		Expect(reg.AuthorizationGrantType).To(Equal(GrantTypeAuthorizationCode))
		Expect(reg.RedirectURI).To(Equal("/login/oauth2/code/google"))
		Expect(reg.Scopes).To(ConsistOf("openid", "profile", "email"))
		Expect(reg.ProviderDetails.AuthorizationURI).To(Equal("https://accounts.google.com/o/oauth2/v2/auth"))
		Expect(reg.ProviderDetails.TokenURI).To(Equal("https://oauth2.googleapis.com/token"))
		Expect(reg.ProviderDetails.UserInfoURI).To(Equal("https://openidconnect.googleapis.com/v1/userinfo"))
		Expect(reg.ProviderDetails.JwkSetURI).To(Equal("https://www.googleapis.com/oauth2/v3/certs"))
		Expect(reg.ProviderDetails.UserNameAttributeName).To(Equal("sub"))
		Expect(reg.ClientName).To(Equal("Google"))
	})
})

var _ = Describe("OAuth2AccessToken", func() {
	It("reports expiration status correctly", func() {
		now := time.Now()
		validToken := OAuth2AccessToken{}.New(TokenTypeBearer, "token-1", now, now.Add(1*time.Hour), []string{"read"})
		Expect(validToken.IsExpired()).To(BeFalse())
		Expect(validToken.GetTokenValue()).To(Equal("token-1"))
		Expect(validToken.GetIssuedAt()).To(Equal(now))

		expiredToken := OAuth2AccessToken{}.New(TokenTypeBearer, "token-2", now.Add(-2*time.Hour), now.Add(-1*time.Hour), []string{"read"})
		Expect(expiredToken.IsExpired()).To(BeTrue())

		noExpiryToken := OAuth2AccessToken{}.New(TokenTypeBearer, "token-3", now, time.Time{}, []string{"read"})
		Expect(noExpiryToken.IsExpired()).To(BeFalse())
	})
})

var _ = Describe("OAuth2User & OidcUser", func() {
	It("provides user attributes and authorities", func() {
		auths := []GrantedAuthority{Authority("ROLE_USER"), Authority("SCOPE_profile")}
		attrs := map[string]any{"sub": "user-42", "email": "test@example.com"}

		user := DefaultOAuth2User{}.New(auths, attrs, "sub")
		Expect(user.GetName()).To(Equal("user-42"))
		Expect(user.GetAttributes()).To(HaveKeyWithValue("email", "test@example.com"))
		Expect(user.GetAuthorities()).To(HaveLen(2))
	})

	It("merges id_token and user_info for OidcUser", func() {
		auths := []GrantedAuthority{Authority("ROLE_USER")}
		//nolint:gosec // mock token in test
		idToken := &OidcIdToken{
			TokenValue: "raw-id-token",
			Claims:     map[string]any{"sub": "oidc-100", "iss": "https://auth.example.com"},
		}
		userInfo := &OidcUserInfo{
			Claims: map[string]any{"name": "Alice Wonderland"},
		}

		oidcUser := DefaultOidcUser{}.New(auths, idToken, userInfo, "sub")
		Expect(oidcUser.GetName()).To(Equal("oidc-100"))
		Expect(oidcUser.GetIdToken().TokenValue).To(Equal("raw-id-token"))
		Expect(oidcUser.GetUserInfo().Claims).To(HaveKeyWithValue("name", "Alice Wonderland"))
		Expect(oidcUser.GetAttributes()).To(HaveKeyWithValue("iss", "https://auth.example.com"))
		Expect(oidcUser.GetAttributes()).To(HaveKeyWithValue("name", "Alice Wonderland"))
	})
})

var _ = Describe("OAuth2AuthenticationToken", func() {
	It("represents an authenticated user principal", func() {
		user := DefaultOAuth2User{}.New(
			[]GrantedAuthority{Authority("ROLE_USER")},
			map[string]any{"sub": "bob"},
			"sub",
		)
		token := OAuth2AuthenticationToken{}.New(user, user.GetAuthorities(), "github")

		Expect(token.IsAuthenticated()).To(BeTrue())
		Expect(token.GetName()).To(Equal("bob"))
		Expect(token.AuthorizedClientRegistrationID).To(Equal("github"))
		Expect(token.GetAuthorities()).To(HaveLen(1))
	})
})

var _ = Describe("OAuth2AuthenticationException", func() {
	It("wraps OAuth2Error and unauthenticated token", func() {
		unauth := OAuth2LoginAuthenticationToken{}.New(
			ClientRegistrationBuilder{}.New("test").ClientID("id").Build(),
			OAuth2AuthorizationExchange{},
		)
		oauthErr := OAuth2Error{
			ErrorCode:        OAuth2ErrorInvalidGrant,
			ErrorDescription: "Code has expired",
		}

		ex := OAuth2AuthenticationException{}.New(oauthErr, unauth)
		Expect(ex.Error()).To(ContainSubstring(OAuth2ErrorInvalidGrant))
		Expect(ex.Error()).To(ContainSubstring("Code has expired"))
		Expect(ex.OAuth2Error().ErrorCode).To(Equal(OAuth2ErrorInvalidGrant))
		Expect(ex.AuthenticationRequest()).To(Equal(unauth))
	})

	It("tests constructors and getters across core types", func() {
		// NewClientRegistration and IssuerURI
		built := NewClientRegistration("test-reg").
			IssuerURI("https://issuer.example.com").
			Build()
		Expect(built.ProviderDetails.IssuerURI).To(Equal("https://issuer.example.com"))

		// Token constructors and getters
		now := time.Now()
		exp := now.Add(time.Hour)
		at := NewOAuth2AccessToken(TokenTypeBearer, "at-val", now, exp, []string{"scope1"})
		Expect(at.GetTokenValue()).To(Equal("at-val"))
		Expect(at.GetIssuedAt()).To(Equal(now))
		Expect(at.GetExpiresAt()).To(Equal(exp))

		rt := NewOAuth2RefreshToken("rt-val", now, exp)
		Expect(rt.GetTokenValue()).To(Equal("rt-val"))
		Expect(rt.GetIssuedAt()).To(Equal(now))
		Expect(rt.GetExpiresAt()).To(Equal(exp))

		// User constructors
		u := NewDefaultOAuth2User([]GrantedAuthority{Authority("ROLE_USER")}, map[string]any{"sub": "usr"}, "sub")
		Expect(u.GetName()).To(Equal("usr"))

		idTok := &OidcIdToken{TokenValue: "id-val", Claims: map[string]any{"sub": "oidc-usr"}}
		uOidc := NewDefaultOidcUser([]GrantedAuthority{Authority("ROLE_USER")}, idTok, nil, "sub")
		Expect(uOidc.GetName()).To(Equal("oidc-usr"))

		// AuthorizedClient constructors
		ac1 := OAuth2AuthorizedClient{}.New(built, "alice", at, rt)
		Expect(ac1.PrincipalName).To(Equal("alice"))
		ac2 := NewOAuth2AuthorizedClient(built, "bob", at, rt)
		Expect(ac2.PrincipalName).To(Equal("bob"))

		// Authentication constructors and GetCredentials
		authToken := NewOAuth2AuthenticationToken(u, u.GetAuthorities(), "reg-1")
		Expect(authToken.GetCredentials()).To(BeEmpty())
		Expect(authToken.GetName()).To(Equal("usr"))

		// GetName with nil and non-OAuth2User principal
		emptyAuth := NewOAuth2AuthenticationToken(nil, nil, "reg-1")
		Expect(emptyAuth.GetName()).To(Equal(""))

		// User with non-string attribute or missing key
		userNonStr := NewDefaultOAuth2User(nil, map[string]any{"sub": 12345}, "")
		Expect(userNonStr.GetName()).To(Equal(""))
		userMissing := NewDefaultOAuth2User(nil, map[string]any{}, "missing")
		Expect(userMissing.GetName()).To(Equal(""))

		// OidcUser with nil tokens and default nameAttributeKey
		bareOidc := DefaultOidcUser{}.New(nil, nil, nil, "")
		Expect(bareOidc.GetName()).To(Equal(""))
		Expect(bareOidc.GetIdToken()).To(BeNil())
		Expect(bareOidc.GetUserInfo()).To(BeNil())

		loginAuth := NewOAuth2LoginAuthenticationToken(built, OAuth2AuthorizationExchange{})
		Expect(loginAuth.GetCredentials()).To(BeEmpty())

		loginAuthWithCode := NewOAuth2LoginAuthenticationToken(built, OAuth2AuthorizationExchange{
			AuthorizationResponse: &OAuth2AuthorizationResponse{Code: "test-code"},
		})
		Expect(loginAuthWithCode.GetCredentials()).To(Equal("test-code"))

		// NewOAuth2AuthenticationException
		ex := NewOAuth2AuthenticationException(OAuth2Error{ErrorCode: "err"}, loginAuth)
		Expect(ex).To(HaveOccurred())
	})
})
