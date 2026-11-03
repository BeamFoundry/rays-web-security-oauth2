package keycloak_test

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	_ "github.com/BeamFoundry/rays-web-security"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/login"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/resourceserver"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/web"
)

type KeycloakResourceServerConfig struct {
	Configuration
}

func (this KeycloakResourceServerConfig) New() *KeycloakResourceServerConfig {
	return &this
}

func (this *KeycloakResourceServerConfig) HttpSecurity() *HttpSecurity {
	return (&HttpSecurityBuilder{}).
		With(OAuth2ResourceServer).
		Realm(realmName).
		And().
		AuthorizedHTTPRequests().
		Paths("/api/admin/**").HasAuthority("ROLE_ADMIN").
		Paths("/api/user/email").HasAuthority("SCOPE_email").
		Paths("/api/user/special").HasAuthority("SCOPE_special").
		Paths("/api/user/**").HasAuthority("ROLE_USER").
		Paths("/api/public/**").PermitAll().
		And().
		AnyRequest().Authenticated().
		Build()
}

func (this *KeycloakResourceServerConfig) JwtDecoder() JwtDecoder {
	jwks := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", keycloakBaseURL, realmName)
	return NewJwxJwtDecoderWithRemoteJWKS(jwks)
}

func (this *KeycloakResourceServerConfig) JwtAuthenticationConverter() JwtAuthenticationConverter {
	return NewDefaultJwtAuthenticationConverter().WithPrincipalClaimName("preferred_username")
}

type KeycloakOpaqueTokenResourceServerConfig struct {
	Configuration
}

func (this KeycloakOpaqueTokenResourceServerConfig) New() *KeycloakOpaqueTokenResourceServerConfig {
	return &this
}

func (this *KeycloakOpaqueTokenResourceServerConfig) HttpSecurity() *HttpSecurity {
	introspectURI := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", keycloakBaseURL, realmName)
	return (&HttpSecurityBuilder{}).
		With(OAuth2ResourceServer).
		OpaqueToken(introspectURI, "rays-service-client", "service-client-secret").
		Realm(realmName).
		And().
		AuthorizedHTTPRequests().
		Paths("/api/public/**").PermitAll().
		Paths("/api/user/email").HasAuthority("SCOPE_email").
		Paths("/api/user/special").HasAuthority("SCOPE_special").
		Paths("/api/user/**").Authenticated().
		And().
		AnyRequest().Authenticated().
		Build()
}

type KeycloakOpaqueTokenBeanResourceServerConfig struct {
	Configuration
}

func (this KeycloakOpaqueTokenBeanResourceServerConfig) New() *KeycloakOpaqueTokenBeanResourceServerConfig {
	return &this
}

func (this *KeycloakOpaqueTokenBeanResourceServerConfig) HttpSecurity() *HttpSecurity {
	return (&HttpSecurityBuilder{}).
		With(OAuth2ResourceServer).
		Realm(realmName).
		And().
		AuthorizedHTTPRequests().
		Paths("/api/user/email").HasAuthority("SCOPE_email").
		Paths("/api/public/**").PermitAll().
		And().
		AnyRequest().Authenticated().
		Build()
}

func (this *KeycloakOpaqueTokenBeanResourceServerConfig) OpaqueTokenIntrospector() OpaqueTokenIntrospector {
	introspectURI := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", keycloakBaseURL, realmName)
	return NewNimbusOpaqueTokenIntrospector(introspectURI, "rays-service-client", "service-client-secret").
		WithPrincipalClaimName("username")
}

var _ = Describe("Keycloak Integration Tests", Ordered, func() {
	var (
		tokenURI    string
		aliceTokens *KeycloakTokens
		aliceToken  string
		bobToken    string
	)

	BeforeAll(func() {
		startKeycloak()
	})

	AfterAll(func() {
		stopKeycloak()
	})

	BeforeEach(func() {
		tokenURI = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakBaseURL, realmName)

		var err error
		aliceTokens, err = obtainUserTokens("alice", "alicepassword")
		Expect(err).NotTo(HaveOccurred())
		Expect(aliceTokens).NotTo(BeNil())
		aliceToken = aliceTokens.AccessToken

		bobToken, err = obtainUserToken("bob", "bobpassword")
		Expect(err).NotTo(HaveOccurred())
		Expect(bobToken).NotTo(BeEmpty())
	})

	Context("Full rays-web-security context with Keycloak", func() {
		var (
			chain SecurityFilterChain
			app   *MockSecurityAppHandler
		)

		BeforeEach(func() {
			AddBeamFor(KeycloakResourceServerConfig{}.New())

			GetContainer().EnableScanning()
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

			chain = GetBeamDefaultInstance[SecurityFilterChain]()
			Expect(chain).NotTo(BeNil())

			app = NewMockSecurityAppHandler()
			app.Get("/api/admin/metrics", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("admin-metrics-ok")); err != nil {
					return err
				}
				return nil
			})
			app.Get("/api/user/profile", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("user-profile-ok")); err != nil {
					return err
				}
				return nil
			})
			app.Get("/api/user/email", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("user-email-ok")); err != nil {
					return err
				}
				return nil
			})
			app.Get("/api/user/special", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("special-ok")); err != nil {
					return err
				}
				return nil
			})
			app.Get("/api/public/ping", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("pong-ok")); err != nil {
					return err
				}
				return nil
			})

			chain.Initialize("primary", app)
		})

		It("allows access to public endpoints without any token", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/public/ping"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)

			Expect(app.Execute(h)).NotTo(HaveOccurred())
			Expect(h.Res.Body.String()).To(Equal("pong-ok"))
			Expect(h.Res.Code).To(Equal(http.StatusOK))
		})

		It("authenticates Alice with Keycloak JWT and grants access to /api/admin/metrics", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/admin/metrics"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+aliceToken)

			Expect(app.Execute(h)).NotTo(HaveOccurred())
			Expect(h.Res.Body.String()).To(Equal("admin-metrics-ok"))
			Expect(h.Res.Code).To(Equal(http.StatusOK))

			holder := GetBeamDefaultInstance[SecurityContextHolder]()
			auth := holder.GetContext().GetAuthentication()
			Expect(auth).NotTo(BeNil())
			Expect(auth.IsAuthenticated()).To(BeTrue())
			Expect(auth.GetName()).To(Equal("alice"))
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("ROLE_ADMIN")))
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("ROLE_USER")))
		})

		It("authenticates Bob and grants access to /api/user/profile", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/profile"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+bobToken)

			Expect(app.Execute(h)).NotTo(HaveOccurred())
			Expect(h.Res.Body.String()).To(Equal("user-profile-ok"))
			Expect(h.Res.Code).To(Equal(http.StatusOK))

			holder := GetBeamDefaultInstance[SecurityContextHolder]()
			auth := holder.GetContext().GetAuthentication()
			Expect(auth).NotTo(BeNil())
			Expect(auth.IsAuthenticated()).To(BeTrue())
			Expect(auth.GetName()).To(Equal("bob"))
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("ROLE_USER")))
			Expect(auth.GetAuthorities()).NotTo(ContainElement(Authority("ROLE_ADMIN")))
		})

		It("denies Bob access to /api/admin/metrics with 403 Forbidden due to role requirement", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/admin/metrics"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+bobToken)

			ex := Try(
				func() {
					RaiseErr(app.Execute(h))
				},
				Catch(func(e SecurityFilterChainException) Error {
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
					Expect(ex.Status()).To(Equal(http.StatusForbidden))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})

		It("grants access to /api/user/email for Alice who has SCOPE_email", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/email"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+aliceToken)

			Expect(app.Execute(h)).NotTo(HaveOccurred())
			Expect(h.Res.Body.String()).To(Equal("user-email-ok"))
			Expect(h.Res.Code).To(Equal(http.StatusOK))
		})

		It("denies Alice access to /api/user/special with 403 Forbidden due to missing SCOPE_special", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/special"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+aliceToken)

			ex := Try(
				func() {
					RaiseErr(app.Execute(h))
				},
				Catch(func(e SecurityFilterChainException) Error {
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
					Expect(ex.Status()).To(Equal(http.StatusForbidden))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})

		It("rejects unauthenticated request to /api/user/profile with 401 Unauthorized", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/profile"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)

			ex := Try(
				func() {
					RaiseErr(app.Execute(h))
				},
				Catch(func(e SecurityFilterChainException) Error {
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
					Expect(ex.Status()).To(Equal(http.StatusUnauthorized))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})

		It("rejects request with a corrupted / tampered Bearer token with 401 Unauthorized", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/profile"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+aliceToken+"tampered")

			ex := Try(
				func() {
					RaiseErr(app.Execute(h))
				},
				Catch(func(e SecurityFilterChainException) Error {
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
					Expect(ex.Status()).To(Equal(http.StatusUnauthorized))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})
	})

	Context("Bearer token resolution methods (pkg/resourceserver)", func() {
		It("resolves bearer token from Authorization header", func() {
			resolver := DefaultBearerTokenResolver{}.New()
			u := ValErr(url.Parse("http://localhost:8080/api/test"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+aliceToken)

			token := resolver.Resolve(h)
			Expect(token).To(Equal(aliceToken))
		})

		It("resolves token from URI query parameter when enabled", func() {
			resolver := DefaultBearerTokenResolver{}.New().WithAllowURIQueryParameter(true)
			u := ValErr(url.Parse("http://localhost:8080/api/test?access_token=" + aliceToken))
			h := NewMockSecurityHandler(HttpMethods.GET, u)

			token := resolver.Resolve(h)
			Expect(token).To(Equal(aliceToken))
		})

		It("ignores URI query parameter token when disabled", func() {
			resolver := DefaultBearerTokenResolver{}.New()
			u := ValErr(url.Parse("http://localhost:8080/api/test?access_token=" + aliceToken))
			h := NewMockSecurityHandler(HttpMethods.GET, u)

			token := resolver.Resolve(h)
			Expect(token).To(BeEmpty())
		})

		It("resolves token from form-encoded body parameter when enabled", func() {
			resolver := DefaultBearerTokenResolver{}.New().WithAllowFormEncodedBodyParameter(true)
			u := ValErr(url.Parse("http://localhost:8080/api/test"))
			h := NewMockSecurityHandler(HttpMethods.POST, u)
			h.SetFormValue("access_token", aliceToken)

			token := resolver.Resolve(h)
			Expect(token).To(Equal(aliceToken))
		})
	})

	Context("JWT Validation Constraints & Claims (pkg/jwt)", func() {
		var (
			realmURL string
			jwksURL  string
		)

		BeforeEach(func() {
			realmURL = fmt.Sprintf("%s/realms/%s", keycloakBaseURL, realmName)
			jwksURL = realmURL + "/protocol/openid-connect/certs"
		})

		It("verifies Keycloak JWT signature and decodes headers and claims", func() {
			decoder := NewJwxJwtDecoderWithRemoteJWKS(jwksURL).WithIssuer(realmURL)
			jwtToken, err := decoder.Decode(aliceToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(jwtToken).NotTo(BeNil())

			Expect(jwtToken.Headers["alg"]).To(Equal("RS256"))
			Expect(jwtToken.Headers["typ"]).To(Equal("JWT"))
			Expect(jwtToken.Headers["kid"]).NotTo(BeNil())
			Expect(jwtToken.Claims["iss"]).To(Equal(realmURL))
			Expect(jwtToken.Claims["preferred_username"]).To(Equal("alice"))
			Expect(jwtToken.Claims["email"]).To(Equal("alice@beamfoundry.fr"))
		})

		It("rejects Keycloak token when decoder expects a different issuer", func() {
			decoder := NewJwxJwtDecoderWithRemoteJWKS(jwksURL).WithIssuer("https://rogue-issuer.example.com")
			_, err := decoder.Decode(aliceToken)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("JwtValidationError"))
		})

		It("rejects Keycloak token when decoder expects a different audience", func() {
			decoder := NewJwxJwtDecoderWithRemoteJWKS(jwksURL).WithAudience("unknown-audience")
			_, err := decoder.Decode(aliceToken)
			Expect(err).To(HaveOccurred())
			Expect(err.Name()).To(Equal("JwtValidationError"))
		})
	})

	Context("Client Credentials grant against Keycloak (pkg/client)", func() {
		It("obtains an M2M access token directly from Keycloak token endpoint", func() {
			reg := ClientRegistrationBuilder{}.New("keycloak-service").
				ClientID("rays-service-client").
				ClientSecret("service-client-secret").
				TokenURI(tokenURI).
				AuthorizationGrantType(GrantTypeClientCredentials).
				Build()

			repo := InMemoryClientRegistrationRepository{}.New(reg)
			authorizedClientService := InMemoryOAuth2AuthorizedClientService{}.New()
			manager := DefaultOAuth2AuthorizedClientManager{}.New(repo, authorizedClientService)

			req := &OAuth2AuthorizeRequest{
				ClientRegistrationID: "keycloak-service",
				PrincipalName:        "service-account",
			}

			client, err := manager.Authorize(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(client).NotTo(BeNil())
			Expect(client.AccessToken).NotTo(BeNil())
			Expect(client.AccessToken.TokenValue).NotTo(BeEmpty())
			Expect(client.AccessToken.TokenType).To(Equal(TokenTypeBearer))
		})
	})

	Context("Refresh Token grant against Keycloak (pkg/client)", func() {
		It("refreshes an expired access token using Keycloak refresh token", func() {
			reg := ClientRegistrationBuilder{}.New("keycloak-web").
				ClientID("rays-web-client").
				ClientSecret("web-client-secret").
				TokenURI(tokenURI).
				AuthorizationGrantType(GrantTypeRefreshToken).
				Build()

			expiredAccessToken := OAuth2AccessToken{}.New(
				TokenTypeBearer,
				aliceTokens.AccessToken,
				time.Now().Add(-2*time.Hour),
				time.Now().Add(-1*time.Hour),
				[]string{"openid", "profile", "email"},
			)

			refreshToken := OAuth2RefreshToken{}.New(
				aliceTokens.RefreshToken,
				time.Now().Add(-2*time.Hour),
				time.Now().Add(24*time.Hour),
			)

			authorizedClient := OAuth2AuthorizedClient{}.New(reg, "alice", expiredAccessToken, refreshToken)

			repo := InMemoryClientRegistrationRepository{}.New(reg)
			service := InMemoryOAuth2AuthorizedClientService{}.New()
			Expect(service.SaveAuthorizedClient(authorizedClient)).NotTo(HaveOccurred())

			manager := DefaultOAuth2AuthorizedClientManager{}.New(
				repo,
				service,
				RefreshTokenAuthorizedClientProvider{}.New(nil),
			)

			req := &OAuth2AuthorizeRequest{
				ClientRegistrationID: "keycloak-web",
				PrincipalName:        "alice",
			}

			refreshedClient, err := manager.Authorize(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(refreshedClient).NotTo(BeNil())
			Expect(refreshedClient.AccessToken).NotTo(BeNil())
			Expect(refreshedClient.AccessToken.TokenValue).NotTo(BeEmpty())
			Expect(refreshedClient.AccessToken.TokenValue).NotTo(Equal(expiredAccessToken.TokenValue))
			Expect(refreshedClient.RefreshToken).NotTo(BeNil())
			Expect(refreshedClient.RefreshToken.TokenValue).NotTo(BeEmpty())

			saved, err := service.LoadAuthorizedClient("keycloak-web", "alice")
			Expect(err).NotTo(HaveOccurred())
			Expect(saved.AccessToken.TokenValue).To(Equal(refreshedClient.AccessToken.TokenValue))
		})
	})

	Context("OIDC UserInfo & ID Token processing (pkg/login)", func() {
		It("fetches user profile from Keycloak userinfo endpoint via DefaultOAuth2UserService", func() {
			userInfoURI := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", keycloakBaseURL, realmName)

			reg := ClientRegistrationBuilder{}.New("keycloak-web").
				ClientID("rays-web-client").
				ClientSecret("web-client-secret").
				UserInfoURI(userInfoURI).
				UserNameAttributeName("preferred_username").
				Build()

			accessToken := OAuth2AccessToken{}.New(
				TokenTypeBearer,
				aliceToken,
				time.Now(),
				time.Now().Add(time.Hour),
				[]string{"openid", "profile", "email"},
			)

			userRequest := &OAuth2UserRequest{
				ClientRegistration: reg,
				AccessToken:        accessToken,
			}

			userService := DefaultOAuth2UserService{}.New(nil)
			user, err := userService.LoadUser(userRequest)

			Expect(err).NotTo(HaveOccurred())
			Expect(user).NotTo(BeNil())
			Expect(user.GetName()).To(Equal("alice"))
			Expect(user.GetAttributes()["preferred_username"]).To(Equal("alice"))
			Expect(user.GetAttributes()["email"]).To(Equal("alice@beamfoundry.fr"))
			Expect(user.GetAttributes()["given_name"]).To(Equal("Alice"))
			Expect(user.GetAttributes()["family_name"]).To(Equal("Beamy"))
		})

		It("loads complete OidcUser combining ID Token and UserInfo claims via DefaultOidcUserService", func() {
			Expect(aliceTokens.IDToken).NotTo(BeEmpty())

			_, idClaims, parseErr := ParseUnverified(aliceTokens.IDToken)
			Expect(parseErr).NotTo(HaveOccurred())

			idToken := &OidcIdToken{
				TokenValue: aliceTokens.IDToken,
				Claims:     idClaims,
			}

			userInfoURI := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", keycloakBaseURL, realmName)
			reg := ClientRegistrationBuilder{}.New("keycloak-web").
				ClientID("rays-web-client").
				ClientSecret("web-client-secret").
				UserInfoURI(userInfoURI).
				UserNameAttributeName("preferred_username").
				Build()

			accessToken := OAuth2AccessToken{}.New(
				TokenTypeBearer,
				aliceToken,
				time.Now(),
				time.Now().Add(time.Hour),
				[]string{"openid", "profile", "email"},
			)

			oidcReq := &OidcUserRequest{
				ClientRegistration: reg,
				AccessToken:        accessToken,
				IdToken:            idToken,
			}

			oidcService := DefaultOidcUserService{}.New(nil)
			oidcUser, err := oidcService.LoadUser(oidcReq)

			Expect(err).NotTo(HaveOccurred())
			Expect(oidcUser).NotTo(BeNil())
			Expect(oidcUser.GetName()).To(Equal("alice"))
			Expect(oidcUser.GetIdToken()).NotTo(BeNil())
			Expect(oidcUser.GetIdToken().TokenValue).To(Equal(aliceTokens.IDToken))
			Expect(oidcUser.GetUserInfo()).NotTo(BeNil())
			Expect(oidcUser.GetUserInfo().Claims["preferred_username"]).To(Equal("alice"))
			Expect(oidcUser.GetUserInfo().Claims["email"]).To(Equal("alice@beamfoundry.fr"))
			Expect(oidcUser.GetUserInfo().Claims["email_verified"]).To(BeTrue())
			Expect(oidcUser.GetAuthorities()).To(ContainElement(Authority("ROLE_USER")))
			Expect(oidcUser.GetAuthorities()).To(ContainElement(Authority("SCOPE_openid")))
			Expect(oidcUser.GetAuthorities()).To(ContainElement(Authority("SCOPE_profile")))
			Expect(oidcUser.GetAuthorities()).To(ContainElement(Authority("SCOPE_email")))
		})
	})

	Context("Opaque Token Introspection against Keycloak (RFC 7662)", func() {
		var introspectURI string

		BeforeEach(func() {
			introspectURI = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", keycloakBaseURL, realmName)
		})

		It("introspects a valid access token using NimbusOpaqueTokenIntrospector", func() {
			introspector := NewNimbusOpaqueTokenIntrospector(
				introspectURI,
				"rays-service-client",
				"service-client-secret",
			)

			principal, err := introspector.Introspect(aliceToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(principal).NotTo(BeNil())

			attrs := principal.GetAttributes()
			Expect(attrs["active"]).To(BeTrue())
			Expect(attrs["client_id"]).To(Equal("rays-web-client"))
			Expect(attrs["username"]).To(Equal("alice"))
			Expect(attrs["sub"]).NotTo(BeEmpty())
			Expect(principal.GetName()).To(Equal(attrs["sub"]))

			authorities := principal.GetAuthorities()
			Expect(authorities).To(ContainElement(Authority("SCOPE_openid")))
			Expect(authorities).To(ContainElement(Authority("SCOPE_profile")))
			Expect(authorities).To(ContainElement(Authority("SCOPE_email")))
		})

		It("extracts custom principal name when principalClaimName is configured", func() {
			introspector := NewNimbusOpaqueTokenIntrospector(
				introspectURI,
				"rays-service-client",
				"service-client-secret",
			).WithPrincipalClaimName("username")

			principal, err := introspector.Introspect(aliceToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(principal).NotTo(BeNil())
			Expect(principal.GetName()).To(Equal("alice"))
		})

		It("fails introspection when client credentials are invalid", func() {
			introspector := NewNimbusOpaqueTokenIntrospector(
				introspectURI,
				"rays-service-client",
				"wrong-client-secret",
			)

			principal, err := introspector.Introspect(aliceToken)
			Expect(err).To(HaveOccurred())
			Expect(principal).To(BeNil())
		})

		It("fails introspection when token is invalid or unrecognized", func() {
			introspector := NewNimbusOpaqueTokenIntrospector(
				introspectURI,
				"rays-service-client",
				"service-client-secret",
			)

			principal, err := introspector.Introspect("invalid-opaque-token-value")
			Expect(err).To(HaveOccurred())
			Expect(principal).To(BeNil())
		})
	})

	Context("Opaque Token Authentication Provider against Keycloak (pkg/resourceserver)", func() {
		var introspectURI string

		BeforeEach(func() {
			introspectURI = fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/introspect", keycloakBaseURL, realmName)
		})

		It("authenticates BearerTokenAuthenticationToken and returns BearerTokenAuthentication", func() {
			introspector := NewNimbusOpaqueTokenIntrospector(
				introspectURI,
				"rays-service-client",
				"service-client-secret",
			).WithPrincipalClaimName("username")

			provider := NewOpaqueTokenAuthenticationProvider(introspector)

			token := BearerTokenAuthenticationToken{}.New(aliceToken)
			Expect(provider.Supports(token)).To(BeTrue())

			auth, err := provider.Authenticate(token)
			Expect(err).NotTo(HaveOccurred())
			Expect(auth).NotTo(BeNil())
			Expect(auth.IsAuthenticated()).To(BeTrue())
			Expect(auth.GetName()).To(Equal("alice"))
			Expect(auth.GetCredentials()).To(Equal(aliceToken))
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("SCOPE_openid")))
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("SCOPE_profile")))
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("SCOPE_email")))

			bearerAuth, ok := auth.(*BearerTokenAuthentication)
			Expect(ok).To(BeTrue())
			Expect(bearerAuth.GetToken()).NotTo(BeNil())
			Expect(bearerAuth.GetToken().TokenValue).To(Equal(aliceToken))
			Expect(bearerAuth.GetAttributes()["client_id"]).To(Equal("rays-web-client"))
		})

		It("rejects invalid bearer token with authentication error", func() {
			introspector := NewNimbusOpaqueTokenIntrospector(
				introspectURI,
				"rays-service-client",
				"service-client-secret",
			)

			provider := NewOpaqueTokenAuthenticationProvider(introspector)

			token := BearerTokenAuthenticationToken{}.New("tampered-token-value")
			auth, err := provider.Authenticate(token)
			Expect(err).To(HaveOccurred())
			Expect(auth.IsAuthenticated()).To(BeFalse())
		})
	})

	Context("Full rays-web-security context with Keycloak Opaque Token (DSL configuration)", func() {
		var (
			chain SecurityFilterChain
			app   *MockSecurityAppHandler
		)

		BeforeEach(func() {
			AddBeamFor(KeycloakOpaqueTokenResourceServerConfig{}.New())

			GetContainer().EnableScanning()
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

			chain = GetBeamDefaultInstance[SecurityFilterChain]()
			Expect(chain).NotTo(BeNil())

			app = NewMockSecurityAppHandler()
			app.Get("/api/public/ping", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("pong-ok")); err != nil {
					return err
				}
				return nil
			})
			app.Get("/api/user/email", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("user-email-ok")); err != nil {
					return err
				}
				return nil
			})
			app.Get("/api/user/special", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("special-ok")); err != nil {
					return err
				}
				return nil
			})
			app.Get("/api/user/profile", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("user-profile-ok")); err != nil {
					return err
				}
				return nil
			})

			chain.Initialize("primary", app)
		})

		It("allows access to public endpoints without any token", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/public/ping"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)

			Expect(app.Execute(h)).NotTo(HaveOccurred())
			Expect(h.Res.Body.String()).To(Equal("pong-ok"))
			Expect(h.Res.Code).To(Equal(http.StatusOK))
		})

		It("authenticates Alice with opaque token introspection and grants access to /api/user/email", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/email"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+aliceToken)

			Expect(app.Execute(h)).NotTo(HaveOccurred())
			Expect(h.Res.Body.String()).To(Equal("user-email-ok"))
			Expect(h.Res.Code).To(Equal(http.StatusOK))

			holder := GetBeamDefaultInstance[SecurityContextHolder]()
			auth := holder.GetContext().GetAuthentication()
			Expect(auth).NotTo(BeNil())
			Expect(auth.IsAuthenticated()).To(BeTrue())
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("SCOPE_email")))
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("SCOPE_profile")))
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("SCOPE_openid")))
		})

		It("denies Alice access to /api/user/special with 403 Forbidden due to missing SCOPE_special", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/special"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+aliceToken)

			ex := Try(
				func() {
					RaiseErr(app.Execute(h))
				},
				Catch(func(e SecurityFilterChainException) Error {
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
					Expect(ex.Status()).To(Equal(http.StatusForbidden))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})

		It("rejects unauthenticated request to /api/user/profile with 401 Unauthorized", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/profile"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)

			ex := Try(
				func() {
					RaiseErr(app.Execute(h))
				},
				Catch(func(e SecurityFilterChainException) Error {
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
					Expect(ex.Status()).To(Equal(http.StatusUnauthorized))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})

		It("rejects request with a corrupted / tampered Bearer token with 401 Unauthorized", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/profile"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+aliceToken+"-invalid")

			ex := Try(
				func() {
					RaiseErr(app.Execute(h))
				},
				Catch(func(e SecurityFilterChainException) Error {
					ex, ok := e.(*DefaultSecurityFilterChainException)
					Expect(ok).To(BeTrue())
					Expect(ex.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
					Expect(ex.Status()).To(Equal(http.StatusUnauthorized))
					return e
				}),
			)
			Expect(ex).To(HaveOccurred())
		})
	})

	Context("Keycloak Opaque Token with Bean Injection", func() {
		var (
			chain SecurityFilterChain
			app   *MockSecurityAppHandler
		)

		BeforeEach(func() {
			AddBeamFor(KeycloakOpaqueTokenBeanResourceServerConfig{}.New())

			GetContainer().EnableScanning()
			Expect(GetContainer().Initialize()).NotTo(HaveOccurred())

			chain = GetBeamDefaultInstance[SecurityFilterChain]()
			Expect(chain).NotTo(BeNil())

			app = NewMockSecurityAppHandler()
			app.Get("/api/user/email", func(h SecurityHandler) error {
				if _, err := h.Write([]byte("user-email-ok")); err != nil {
					return err
				}
				return nil
			})

			chain.Initialize("primary", app)
		})

		It("authenticates Alice and sets principal name to username from bean introspector", func() {
			u := ValErr(url.Parse("http://localhost:8080/api/user/email"))
			h := NewMockSecurityHandler(HttpMethods.GET, u)
			h.Req.Header.Set("Authorization", "Bearer "+aliceToken)

			Expect(app.Execute(h)).NotTo(HaveOccurred())
			Expect(h.Res.Body.String()).To(Equal("user-email-ok"))
			Expect(h.Res.Code).To(Equal(http.StatusOK))

			holder := GetBeamDefaultInstance[SecurityContextHolder]()
			auth := holder.GetContext().GetAuthentication()
			Expect(auth).NotTo(BeNil())
			Expect(auth.IsAuthenticated()).To(BeTrue())
			Expect(auth.GetName()).To(Equal("alice"))
			Expect(auth.GetAuthorities()).To(ContainElement(Authority("SCOPE_email")))
		})
	})
})
