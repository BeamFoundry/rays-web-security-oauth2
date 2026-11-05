// Package config_test contains unit tests for the OAuth 2.0 HttpSecurityBuilder configurers DSL.
package config_test

import (
	"context"
	"testing"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/client"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/login"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/resourceserver"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/server"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/core"
	_ "github.com/BeamFoundry/rays/pkg/testing"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// TestConfig runs the Ginkgo test suite for the OAuth2 config package.
func TestConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OAuth2 Config Suite")
}

// mockAuthManager is a test double for AuthenticationManager that returns the input Authentication unchanged.
type mockAuthManager struct {
	Manager
}

// Authenticate returns the supplied Authentication without error.
func (this *mockAuthManager) Authenticate(a Authentication) (Authentication, AuthenticationException) {
	return a, nil
}

// mockSecurityContextHolder is an in-memory test double for SecurityContextHolder.
type mockSecurityContextHolder struct {
	ctx SecurityContext
}

// ClearContext resets the stored SecurityContext to nil.
func (this *mockSecurityContextHolder) ClearContext() { this.ctx = nil }

// SetContext stores the given SecurityContext.
func (this *mockSecurityContextHolder) SetContext(sc SecurityContext) { this.ctx = sc }

// GetContext returns the currently stored SecurityContext.
func (this *mockSecurityContextHolder) GetContext() SecurityContext { return this.ctx }

var _ = Describe("OAuth2 Configurers DSL", func() {
	var (
		builder       *HttpSecurityBuilder
		authManager   *mockAuthManager
		contextHolder *mockSecurityContextHolder
	)

	BeforeEach(func() {
		builder = &HttpSecurityBuilder{}
		authManager = &mockAuthManager{}
		contextHolder = &mockSecurityContextHolder{}
	})

	Context("OAuth2LoginConfigurer", func() {
		It("configures OAuth2 Login via With(OAuth2Login) and attaches filter config to HttpSecurityBuilder", func() {
			reg := ClientRegistrationBuilder{}.New("google").
				ClientID("g-id").
				ClientSecret("g-sec").
				Build()
			repo := InMemoryClientRegistrationRepository{}.New(reg)

			chain := (&HttpSecurityBuilder{}).
				With(OAuth2Login).
				ClientRegistrationRepository(repo).
				AuthenticationManager(authManager).
				SecurityContextHolder(contextHolder).
				DefaultRegistrationID("google").
				DefaultSuccessURL("/home").
				And().
				Build()

			Expect(chain).NotTo(BeNil())
			Expect(chain.SecurityFilters()).To(HaveKey("oAuth2LoginAuthenticationFilter"))

			cfg, ok := chain.SecurityFilters()["oAuth2LoginAuthenticationFilter"].(*OAuth2LoginConfig)
			Expect(ok).To(BeTrue())
			Expect(cfg.ClientRegistrationRepository).To(Equal(repo))
			Expect(cfg.AuthenticationManager).To(Equal(authManager))
			Expect(cfg.SecurityContextHolder).To(Equal(contextHolder))
			Expect(cfg.DefaultRegistrationID).To(Equal("google"))
			Expect(cfg.DefaultSuccessURL).To(Equal("/home"))
		})

		It("configures OAuth2 Login via direct OAuth2Login(builder)", func() {
			reg := ClientRegistrationBuilder{}.New("google").
				ClientID("g-id").
				ClientSecret("g-sec").
				Build()
			repo := InMemoryClientRegistrationRepository{}.New(reg)

			OAuth2Login(builder).
				ClientRegistrationRepository(repo).
				DefaultRegistrationID("google").
				And()

			chain := builder.Build()
			Expect(chain).NotTo(BeNil())
			Expect(chain.SecurityFilters()).To(HaveKey("oAuth2LoginAuthenticationFilter"))
		})

		It("activates OAuth2LoginAuthenticationFilter when injected into HttpSecurity with matching config", func() {
			reg := ClientRegistrationBuilder{}.New("google").
				ClientID("g-id").
				ClientSecret("g-sec").
				Build()
			repo := InMemoryClientRegistrationRepository{}.New(reg)

			chain := (&HttpSecurityBuilder{}).
				With(OAuth2Login).
				ClientRegistrationRepository(repo).
				DefaultRegistrationID("google").
				And().
				Build()

			filter := &OAuth2LoginAuthenticationFilter{}
			ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, chain)

			Expect(filter.WithContext(ctx)).NotTo(HaveOccurred())
			Expect(filter.Config()).NotTo(BeNil())
			Expect(filter.Config().DefaultRegistrationID).To(Equal("google"))
		})

		It("rejects OAuth2LoginAuthenticationFilter when HttpSecurity does not configure it", func() {
			chain := builder.Build()
			filter := &OAuth2LoginAuthenticationFilter{}
			ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, chain)

			err := filter.WithContext(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("HttpSecurity does not configure oAuth2LoginAuthenticationFilter"))
		})
	})

	Context("OAuth2ResourceServerConfigurer", func() {
		It("configures Resource Server Bearer authentication via With(OAuth2ResourceServer)", func() {
			chain := (&HttpSecurityBuilder{}).
				With(OAuth2ResourceServer).
				AuthenticationManager(authManager).
				SecurityContextHolder(contextHolder).
				Realm("my-api-realm").
				And().
				Build()

			Expect(chain).NotTo(BeNil())
			Expect(chain.SecurityFilters()).To(HaveKey("bearerTokenAuthenticationFilter"))

			cfg, ok := chain.SecurityFilters()["bearerTokenAuthenticationFilter"].(*BearerTokenConfig)
			Expect(ok).To(BeTrue())
			Expect(cfg.AuthenticationManager).To(Equal(authManager))
			Expect(cfg.SecurityContextHolder).To(Equal(contextHolder))
			Expect(cfg.RealmName).To(Equal("my-api-realm"))
		})

		It("configures Resource Server Bearer authentication via direct OAuth2ResourceServer(builder)", func() {
			OAuth2ResourceServer(builder).
				Realm("my-api-realm").
				And()

			chain := builder.Build()
			Expect(chain).NotTo(BeNil())
			Expect(chain.SecurityFilters()).To(HaveKey("bearerTokenAuthenticationFilter"))
		})

		It("activates BearerTokenAuthenticationFilter when injected into HttpSecurity with matching config", func() {
			chain := (&HttpSecurityBuilder{}).
				With(OAuth2ResourceServer).
				Realm("my-api-realm").
				And().
				Build()

			filter := &BearerTokenAuthenticationFilter{}
			ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, chain)

			Expect(filter.WithContext(ctx)).NotTo(HaveOccurred())
			Expect(filter.Config()).NotTo(BeNil())
			Expect(filter.Config().RealmName).To(Equal("my-api-realm"))
		})

		It("rejects BearerTokenAuthenticationFilter when HttpSecurity does not configure it", func() {
			chain := builder.Build()
			filter := &BearerTokenAuthenticationFilter{}
			ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, chain)

			err := filter.WithContext(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("HttpSecurity does not configure bearerTokenAuthenticationFilter"))
		})

		It("configures Resource Server Opaque Token introspection via OpaqueToken() and OpaqueTokenIntrospector()", func() {
			chain := (&HttpSecurityBuilder{}).
				With(OAuth2ResourceServer).
				OpaqueToken("https://auth.example.com/oauth2/introspect", "client-rs", "secret-rs").
				And().
				Build()

			cfg, ok := chain.SecurityFilters()["bearerTokenAuthenticationFilter"].(*BearerTokenConfig)
			Expect(ok).To(BeTrue())
			Expect(cfg.OpaqueTokenIntrospector).NotTo(BeNil())

			customIntrospector := NewNimbusOpaqueTokenIntrospector("https://auth.example.com/oauth2/introspect", "id", "sec")
			chain2 := (&HttpSecurityBuilder{}).
				With(OAuth2ResourceServer).
				OpaqueTokenIntrospector(customIntrospector).
				And().
				Build()

			cfg2, ok := chain2.SecurityFilters()["bearerTokenAuthenticationFilter"].(*BearerTokenConfig)
			Expect(ok).To(BeTrue())
			Expect(cfg2.OpaqueTokenIntrospector).To(Equal(customIntrospector))
		})
	})

	Context("OAuth2AuthorizationServerConfigurer", func() {
		It("configures Authorization Server endpoints via With(OAuth2AuthorizationServer)", func() {
			km, err := RSAKeyManager{}.New(2048, "key-cfg")
			Expect(err).NotTo(HaveOccurred())

			clientRepo := InMemoryRegisteredClientRepository{}.New()
			authService := InMemoryOAuth2AuthorizationService{}.New()

			chain := (&HttpSecurityBuilder{}).
				With(OAuth2AuthorizationServer).
				RegisteredClientRepository(clientRepo).
				AuthorizationService(authService).
				JWKSource(km).
				SecurityContextHolder(contextHolder).
				And().
				Build()

			Expect(chain).NotTo(BeNil())
			Expect(chain.SecurityFilters()).To(HaveKey("oAuth2AuthorizationServerFilter"))

			cfg, ok := chain.SecurityFilters()["oAuth2AuthorizationServerFilter"].(*OAuth2AuthorizationServerConfig)
			Expect(ok).To(BeTrue())
			Expect(cfg.ClientRepository).To(Equal(clientRepo))
			Expect(cfg.AuthorizationService).To(Equal(authService))
			Expect(cfg.JWKSource).To(Equal(km))
			Expect(cfg.SecurityContextHolder).To(Equal(contextHolder))
		})

		It("configures Authorization Server endpoints via direct OAuth2AuthorizationServer(builder)", func() {
			clientRepo := InMemoryRegisteredClientRepository{}.New()
			authService := InMemoryOAuth2AuthorizationService{}.New()

			OAuth2AuthorizationServer(builder).
				RegisteredClientRepository(clientRepo).
				AuthorizationService(authService).
				And()

			chain := builder.Build()
			Expect(chain).NotTo(BeNil())
			Expect(chain.SecurityFilters()).To(HaveKey("oAuth2AuthorizationServerFilter"))
		})

		It("activates OAuth2AuthorizationServerFilter when injected into HttpSecurity with matching config", func() {
			clientRepo := InMemoryRegisteredClientRepository{}.New()
			authService := InMemoryOAuth2AuthorizationService{}.New()

			chain := (&HttpSecurityBuilder{}).
				With(OAuth2AuthorizationServer).
				RegisteredClientRepository(clientRepo).
				AuthorizationService(authService).
				And().
				Build()

			filter := &OAuth2AuthorizationServerFilter{}
			ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, chain)

			Expect(filter.WithContext(ctx)).NotTo(HaveOccurred())
			Expect(filter.Config()).NotTo(BeNil())
			Expect(filter.Config().ClientRepository).To(Equal(clientRepo))
		})

		It("rejects OAuth2AuthorizationServerFilter when HttpSecurity does not configure it", func() {
			chain := builder.Build()
			filter := &OAuth2AuthorizationServerFilter{}
			ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, chain)

			err := filter.WithContext(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("HttpSecurity does not configure oAuth2AuthorizationServerFilter"))
		})

		It("tests all configurer options and constructors", func() {
			// Login configurer
			loginConf := NewOAuth2LoginConfigurer(builder).
				AuthorizationRequestRepository(SessionAuthorizationRequestRepository{}.New()).
				LoginProcessingURL("/login/oauth2/code/*").
				AuthorizationBaseURI("/oauth2/authorization").
				BaseURL("https://example.com").
				TrustedProxy(true)
			Expect(loginConf.And()).To(Equal(builder))

			// Resource server configurer
			rsConf := NewOAuth2ResourceServerConfigurer(builder).
				TokenResolver(DefaultBearerTokenResolver{}.New()).
				JwtDecoder(NimbusJwtDecoder{}.New(nil))
			Expect(rsConf.And()).To(Equal(builder))

			// Auth server configurer
			asConf := NewOAuth2AuthorizationServerConfigurer(builder).
				Settings(AuthorizationServerSettings{}.NewDefault("https://issuer.com")).
				TokenGenerator(JwtOAuth2TokenGenerator{}.New(nil, "https://issuer.com"))
			Expect(asConf.And()).To(Equal(builder))
		})
	})
})
