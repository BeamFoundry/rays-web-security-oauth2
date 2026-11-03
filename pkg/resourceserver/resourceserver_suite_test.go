package resourceserver_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/resourceserver"
	. "github.com/BeamFoundry/rays-web-security/pkg/config"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/testing"
	. "github.com/BeamFoundry/rays/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
	. "github.com/BeamFoundry/rays/pkg/web"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestResourceServer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OAuth2 Resource Server Suite")
}

type mockAuthManager struct {
	Manager
	authenticateFunc func(Authentication) (Authentication, AuthenticationException)
}

func (this *mockAuthManager) Authenticate(auth Authentication) (Authentication, AuthenticationException) {
	if this.authenticateFunc != nil {
		return this.authenticateFunc(auth)
	}
	return auth, nil
}

type mockSecurityContext struct {
	auth  Authentication
	debug string
}

func (this *mockSecurityContext) GetAuthentication() Authentication    { return this.auth }
func (this *mockSecurityContext) SetAuthentication(a Authentication)   { this.auth = a }
func (this *mockSecurityContext) SetHTTPPolicyDebugValue(debug string) { this.debug = debug }
func (this *mockSecurityContext) GetHTTPPolicyDebugValue() string      { return this.debug }

type mockSecurityContextHolder struct {
	ctx SecurityContext
}

func (this *mockSecurityContextHolder) ClearContext() { this.ctx = nil }
func (this *mockSecurityContextHolder) SetContext(sc SecurityContext) {
	this.ctx = sc
}

func (this *mockSecurityContextHolder) GetContext() SecurityContext {
	if this.ctx == nil {
		this.ctx = &mockSecurityContext{}
	}
	return this.ctx
}

var _ = Describe("BearerTokenResolver", func() {
	It("extracts Bearer token from Authorization header", func() {
		u, err := url.Parse("https://api.example.com/orders")
		Expect(err).NotTo(HaveOccurred())
		handler := NewMockSecurityHandler(HttpMethods.GET, u)
		handler.SetHeader("Authorization", "Bearer my-secret-token")

		resolver := DefaultBearerTokenResolver{}.New()
		Expect(resolver.Resolve(handler)).To(Equal("my-secret-token"))
	})

	It("handles case-insensitive 'bearer' prefix", func() {
		u, err := url.Parse("https://api.example.com/orders")
		Expect(err).NotTo(HaveOccurred())
		handler := NewMockSecurityHandler(HttpMethods.GET, u)
		handler.SetHeader("Authorization", "bearer my-lowercase-token")

		resolver := DefaultBearerTokenResolver{}.New()
		Expect(resolver.Resolve(handler)).To(Equal("my-lowercase-token"))
	})

	It("extracts access token from query parameter when allowed", func() {
		u, err := url.Parse("https://api.example.com/orders?access_token=query-token-value")
		Expect(err).NotTo(HaveOccurred())
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		// Without allowing query param
		resolver := DefaultBearerTokenResolver{}.New()
		Expect(resolver.Resolve(handler)).To(BeEmpty())

		// With allowing query param
		resolver.WithAllowURIQueryParameter(true)
		Expect(resolver.Resolve(handler)).To(Equal("query-token-value"))
	})
})

var _ = Describe("JwtAuthenticationConverter", func() {
	It("converts space-delimited scope string into GrantedAuthorities with prefix", func() {
		tok := &Jwt{
			TokenValue: "raw",
			Headers:    map[string]any{"alg": "RS256"},
			Claims: map[string]any{
				"sub":   "user-99",
				"scope": "read write delete",
			},
		}

		converter := DefaultJwtAuthenticationConverter{}.New()
		converted, err := converter.Convert(tok)
		Expect(err).NotTo(HaveOccurred())
		Expect(converted.GetName()).To(Equal("user-99"))

		authorities := converted.GetAuthorities()
		var names []string
		for _, a := range authorities {
			names = append(names, a.Authority())
		}
		Expect(names).To(ConsistOf("SCOPE_read", "SCOPE_write", "SCOPE_delete"))
	})

	It("supports custom principal claim name and authority prefix", func() {
		tok := &Jwt{
			TokenValue: "raw",
			Headers:    map[string]any{"alg": "RS256"},
			Claims: map[string]any{
				"sub":      "internal-id",
				"username": "superadmin",
				"roles":    []any{"ADMIN", "MANAGER"},
			},
		}

		converter := DefaultJwtAuthenticationConverter{}.New().
			WithPrincipalClaimName("username").
			WithAuthorityPrefix("ROLE_")

		converted, err := converter.Convert(tok)
		Expect(err).NotTo(HaveOccurred())
		Expect(converted.GetName()).To(Equal("superadmin"))

		var names []string
		for _, a := range converted.GetAuthorities() {
			names = append(names, a.Authority())
		}
		Expect(names).To(ConsistOf("ROLE_ADMIN", "ROLE_MANAGER"))
	})

	It("always applies configured authorityPrefix to scope/scp claims and preserves passthrough for role-style claims", func() {
		tok := &Jwt{
			TokenValue: "raw",
			Headers:    map[string]any{"alg": "RS256"},
			Claims: map[string]any{
				"sub":   "user-100",
				"scope": "ROLE_admin SCOPE_read write",
				"roles": []any{"ROLE_USER", "SCOPE_CUSTOM", "AUDITOR"},
			},
		}

		converter := DefaultJwtAuthenticationConverter{}.New()
		converted, err := converter.Convert(tok)
		Expect(err).NotTo(HaveOccurred())

		var names []string
		for _, a := range converted.GetAuthorities() {
			names = append(names, a.Authority())
		}
		Expect(names).To(ConsistOf(
			"SCOPE_ROLE_admin",
			"SCOPE_SCOPE_read",
			"SCOPE_write",
			"ROLE_USER",
			"SCOPE_CUSTOM",
			"SCOPE_AUDITOR",
		))

		emptyPrefixConv := DefaultJwtAuthenticationConverter{}.New().WithAuthorityPrefix("")
		convertedEmpty, err := emptyPrefixConv.Convert(tok)
		Expect(err).NotTo(HaveOccurred())

		var emptyNames []string
		for _, a := range convertedEmpty.GetAuthorities() {
			emptyNames = append(emptyNames, a.Authority())
		}
		Expect(emptyNames).To(ConsistOf(
			"ROLE_admin",
			"SCOPE_read",
			"write",
			"ROLE_USER",
			"SCOPE_CUSTOM",
			"AUDITOR",
		))
	})
})

var _ = Describe("JwtAuthenticationProvider", func() {
	It("authenticates a valid Bearer token and returns JwtAuthenticationToken", func() {
		km, err := RSAKeyManager{}.New(2048, "rs-test-key")
		Expect(err).NotTo(HaveOccurred())

		encoder := DefaultJwtEncoder{}.New(km)
		now := time.Now()
		claimsSet := JwtClaimsSet{}.New()
		claimsSet.Issuer = "https://auth.example.com"
		claimsSet.Subject = "alice"
		claimsSet.IssuedAt = now
		claimsSet.ExpiresAt = now.Add(30 * time.Minute)
		claimsSet.Claims["scope"] = "read write admin"

		token, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claimsSet})
		Expect(err).NotTo(HaveOccurred())

		decoder := NimbusJwtDecoder{}.New(km).WithIssuer("https://auth.example.com")
		provider := JwtAuthenticationProvider{}.New(decoder)

		bearerToken := BearerTokenAuthenticationToken{}.New(token.TokenValue)
		Expect(provider.Supports(bearerToken)).To(BeTrue())

		auth, authEx := provider.Authenticate(bearerToken)
		Expect(authEx).NotTo(HaveOccurred())
		Expect(auth.IsAuthenticated()).To(BeTrue())
		Expect(auth.GetName()).To(Equal("alice"))

		var authNames []string
		for _, a := range auth.GetAuthorities() {
			authNames = append(authNames, a.Authority())
		}
		Expect(authNames).To(ConsistOf("SCOPE_read", "SCOPE_write", "SCOPE_admin"))
	})

	It("fails authentication when token is invalid or expired", func() {
		km, err := RSAKeyManager{}.New(2048, "rs-test-key")
		Expect(err).NotTo(HaveOccurred())

		decoder := NimbusJwtDecoder{}.New(km).WithIssuer("https://auth.example.com")
		provider := JwtAuthenticationProvider{}.New(decoder)

		bearerToken := BearerTokenAuthenticationToken{}.New("invalid.jwt.token")
		_, authEx := provider.Authenticate(bearerToken)
		Expect(authEx).To(HaveOccurred())
	})
})

var _ = Describe("BearerTokenAuthenticationFilter", func() {
	var (
		authManager   *mockAuthManager
		contextHolder *mockSecurityContextHolder
		filter        *BearerTokenAuthenticationFilter
	)

	BeforeEach(func() {
		authManager = &mockAuthManager{}
		contextHolder = &mockSecurityContextHolder{}
		filter = BearerTokenAuthenticationFilter{}.New(authManager, contextHolder)
	})

	It("authenticates request and populates SecurityContext when Bearer token is present", func() {
		u, err := url.Parse("https://api.example.com/resource")
		Expect(err).NotTo(HaveOccurred())
		handler := NewMockSecurityHandler(HttpMethods.GET, u)
		handler.SetHeader("Authorization", "Bearer valid-token")

		authManager.authenticateFunc = func(_ Authentication) (Authentication, AuthenticationException) {
			tok := &Jwt{
				TokenValue: "valid-token",
				Claims:     map[string]any{"sub": "bob"},
			}
			return JwtAuthenticationToken{}.New(tok, []GrantedAuthority{Authority("SCOPE_read")}, "bob"), nil
		}

		chainEx := filter.Authenticate(handler)
		Expect(chainEx).To(HaveOccurred())
		Expect(chainEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))

		ctxAuth := contextHolder.GetContext().GetAuthentication()
		Expect(ctxAuth).NotTo(BeNil())
		Expect(ctxAuth.GetName()).To(Equal("bob"))
	})

	It("passes through to next filter when no Bearer token is present", func() {
		u, err := url.Parse("https://api.example.com/public")
		Expect(err).NotTo(HaveOccurred())
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		chainEx := filter.Authenticate(handler)
		Expect(chainEx).To(HaveOccurred())
		Expect(chainEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))
		Expect(contextHolder.GetContext().GetAuthentication()).To(BeNil())
	})

	It("sets WWW-Authenticate header and returns 401 when AuthenticationRequired is invoked", func() {
		u, err := url.Parse("https://api.example.com/protected")
		Expect(err).NotTo(HaveOccurred())
		handler := NewMockSecurityHandler(HttpMethods.GET, u)

		chainEx := filter.AuthenticationRequired(handler)
		Expect(chainEx).To(HaveOccurred())
		defaultEx, ok := chainEx.(*DefaultSecurityFilterChainException)
		Expect(ok).To(BeTrue())
		Expect(defaultEx.Status()).To(Equal(401))
		Expect(handler.Header("WWW-Authenticate")).To(Equal(`Bearer realm="rays-web-security-oauth2"`))
	})

	It("supports WithTokenResolver, WithRealmName, Config and constructors", func() {
		customResolver := NewDefaultBearerTokenResolver().WithAllowFormEncodedBodyParameter(true)
		f := NewBearerTokenAuthenticationFilter(authManager, contextHolder).
			WithTokenResolver(customResolver).
			WithRealmName("custom-realm")

		Expect(f.Config()).NotTo(BeNil())
		Expect(f.Config().RealmName).To(Equal("custom-realm"))

		u, err := url.Parse("https://api.example.com/post-resource")
		Expect(err).NotTo(HaveOccurred())
		handler := NewMockSecurityHandler(HttpMethods.POST, u)
		handler.SetFormValue("access_token", "form-body-token")

		Expect(customResolver.Resolve(handler)).To(Equal("form-body-token"))

		authManager.authenticateFunc = func(_ Authentication) (Authentication, AuthenticationException) {
			tok := &Jwt{
				TokenValue: "form-body-token",
				Claims:     map[string]any{"sub": "form-user"},
			}
			return NewJwtAuthenticationToken(tok, []GrantedAuthority{Authority("ROLE_USER")}, "form-user"), nil
		}

		chainEx := f.Authenticate(handler)
		Expect(chainEx).To(HaveOccurred())
		Expect(chainEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))

		ctxAuth := contextHolder.GetContext().GetAuthentication()
		Expect(ctxAuth).NotTo(BeNil())
		Expect(ctxAuth.GetName()).To(Equal("form-user"))
		Expect(ctxAuth.GetCredentials()).To(Equal("form-body-token"))
	})
})

var _ = Describe("ResourceServer Additional Coverage", func() {
	It("tests JwtAuthenticationConverter with dotted claims and duplicate prefixes", func() {
		tok := &Jwt{
			TokenValue: "raw",
			Headers:    map[string]any{"alg": "RS256"},
			Claims: map[string]any{
				"sub": "test-sub",
				"realm_access": map[string]any{
					"roles": []any{"ROLE_ADMIN", "REGULAR"},
				},
				"resource_access": map[string]any{
					"my-app": map[string]any{
						"roles": []string{"CLIENT_ROLE"},
					},
				},
			},
		}

		conv := NewDefaultJwtAuthenticationConverter().
			WithAuthoritiesClaims("realm_access.roles", "resource_access.my-app.roles").
			WithAuthorityPrefix("SCOPE_")

		auth, err := conv.Convert(tok)
		Expect(err).NotTo(HaveOccurred())
		Expect(auth.GetName()).To(Equal("test-sub"))

		var authNames []string
		for _, a := range auth.GetAuthorities() {
			authNames = append(authNames, a.Authority())
		}
		Expect(authNames).To(ContainElement("ROLE_ADMIN"))
		Expect(authNames).To(ContainElement("SCOPE_REGULAR"))
		Expect(authNames).To(ContainElement("SCOPE_CLIENT_ROLE"))
	})

	It("tests JwtAuthenticationProvider constructors, PostConstruct and edge cases", func() {
		p := NewJwtAuthenticationProvider(nil)
		Expect(p.PostConstruct()).NotTo(HaveOccurred())

		// When jwtDecoder is nil
		bearerTok := NewBearerTokenAuthenticationToken("some-tok")
		Expect(bearerTok.GetCredentials()).To(Equal("some-tok"))

		_, authEx := p.Authenticate(bearerTok)
		Expect(authEx).To(HaveOccurred())

		// When auth is not BearerTokenAuthenticationToken
		otherAuth := OAuth2AuthenticationToken{}.New(nil, nil, "some-reg")
		_, authEx = p.Authenticate(otherAuth)
		Expect(authEx).To(HaveOccurred())

		// WithConverter
		conv := NewDefaultJwtAuthenticationConverter()
		Expect(p.WithConverter(conv)).To(Equal(p))
	})

	It("tests BearerTokenAuthenticationFilter WithContext lifecycle", func() {
		filter := &BearerTokenAuthenticationFilter{}

		// Non-HttpSecurity context parent returns error
		invalidCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, "not-http-security")
		err := filter.WithContext(invalidCtx)
		Expect(err).To(HaveOccurred())
		Expect(err.Name()).To(Equal("IllegalArgumentException"))

		// HttpSecurity missing filter config returns error
		builderEmpty := &HttpSecurityBuilder{}
		secEmpty := builderEmpty.Build()
		missingCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, secEmpty)
		err = filter.WithContext(missingCtx)
		Expect(err).To(HaveOccurred())
		Expect(err.Name()).To(Equal("IllegalArgumentException"))

		// HttpSecurity with invalid config type returns error
		builderInvalid := &HttpSecurityBuilder{}
		builderInvalid.AddCustomSecurityFilter("bearerTokenAuthenticationFilter", "wrong-type")
		secInvalid := builderInvalid.Build()
		invalidCfgCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, secInvalid)
		err = filter.WithContext(invalidCfgCtx)
		Expect(err).To(HaveOccurred())
		Expect(err.Name()).To(Equal("IllegalArgumentException"))

		// HttpSecurity with valid BearerTokenConfig
		builderValid := &HttpSecurityBuilder{}
		cfg := &BearerTokenConfig{
			RealmName: "custom-realm-via-context",
		}
		builderValid.AddCustomSecurityFilter("bearerTokenAuthenticationFilter", cfg)
		secValid := builderValid.Build()
		validCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, secValid)
		err = filter.WithContext(validCtx)
		Expect(err).NotTo(HaveOccurred())
		Expect(filter.Config().RealmName).To(Equal("custom-realm-via-context"))

		// WithContext with background context (no parent) applies defaults
		filterNoParent := &BearerTokenAuthenticationFilter{}
		err = filterNoParent.WithContext(context.Background())
		Expect(err).NotTo(HaveOccurred())
		Expect(filterNoParent.Config().RealmName).To(Equal("rays-web-security-oauth2"))

		// AuthenticationRequired issues 401 with WWW-Authenticate header
		reqURL, parseErr := url.Parse("https://api.example.com/protected")
		Expect(parseErr).NotTo(HaveOccurred())
		h := NewMockSecurityHandler(HttpMethods.GET, reqURL)
		authEx := filterNoParent.AuthenticationRequired(h)
		Expect(authEx).To(HaveOccurred())
		Expect(authEx.Action()).To(Equal(DefaultSecurityFilterAction{}.New().ERROR.Name()))
		Expect(h.Header("WWW-Authenticate")).To(Equal(`Bearer realm="rays-web-security-oauth2"`))

		// BearerTokenAuthenticationToken getters
		bTok := NewBearerTokenAuthenticationToken("tok-123")
		Expect(bTok.GetCredentials()).To(Equal("tok-123"))

		// JwtAuthenticationToken getters with explicit name vs Jwt subject fallback
		jwtAuthStr := NewJwtAuthenticationToken(nil, nil, "string-principal")
		Expect(jwtAuthStr.GetName()).To(Equal("string-principal"))
		Expect(jwtAuthStr.GetCredentials()).To(BeEmpty())

		jwtWithSub := NewJwt("tok-val", time.Time{}, time.Time{}, nil, map[string]any{"sub": "jwt-sub"})
		jwtAuthUser := NewJwtAuthenticationToken(jwtWithSub, nil, "")
		Expect(jwtAuthUser.GetName()).To(Equal("jwt-sub"))
		Expect(jwtAuthUser.GetCredentials()).To(Equal("tok-val"))

		jwtAuthEmpty := NewJwtAuthenticationToken(nil, nil, "")
		Expect(jwtAuthEmpty.GetName()).To(BeEmpty())
		Expect(jwtAuthEmpty.GetCredentials()).To(BeEmpty())

		// Failing converter
		km, keyErr := RSAKeyManager{}.New(2048, "conv-err-key")
		Expect(keyErr).NotTo(HaveOccurred())
		encoder := NewDefaultJwtEncoder(km)
		tok, encErr := encoder.Encode(&JwtEncoderParameters{ClaimsSet: NewJwtClaimsSet()})
		Expect(encErr).NotTo(HaveOccurred())
		dec := NewNimbusJwtDecoder(km)
		failingProv := NewJwtAuthenticationProvider(dec).WithConverter(&failingJwtConverter{})
		_, authErr := failingProv.Authenticate(NewBearerTokenAuthenticationToken(tok.TokenValue))
		Expect(authErr).To(HaveOccurred())
		// DI Injection & PostConstruct on JwtAuthenticationProvider
		provDI := &JwtAuthenticationProvider{}
		provDI.SetInjectedDecoderForTest(dec)
		customConv := NewDefaultJwtAuthenticationConverter()
		provDI.SetInjectedConverterForTest(customConv)
		Expect(provDI.PostConstruct()).To(Succeed())
		Expect(provDI.GetDecoderForTest()).To(Equal(dec))
		Expect(provDI.GetConverterForTest()).To(Equal(customConv))

		// PostConstruct with defaults when no injected fields
		provDef := &JwtAuthenticationProvider{}
		Expect(provDef.PostConstruct()).To(Succeed())
		Expect(provDef.GetConverterForTest()).NotTo(BeNil())

		// JwtAuthenticationProvider.Authenticate with non-BearerTokenAuthenticationToken
		_, nonBearerErr := provDef.Authenticate(&mockSimpleAuth{})
		Expect(nonBearerErr).To(HaveOccurred())

		// JwtAuthenticationProvider.Authenticate with nil decoder
		provNoDec := &JwtAuthenticationProvider{}
		_, noDecErr := provNoDec.Authenticate(NewBearerTokenAuthenticationToken("some-tok"))
		Expect(noDecErr).To(HaveOccurred())

		// BearerTokenAuthenticationFilter.WithContext prototype lifecycle tests
		bearerFilter := &BearerTokenAuthenticationFilter{}
		// Non-HttpSecurity in context
		badCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, "not-http-security")
		Expect(bearerFilter.WithContext(badCtx)).To(HaveOccurred())

		// HttpSecurity without bearerTokenAuthenticationFilter in SecurityFilters
		emptySec := (&HttpSecurityBuilder{}).Build()
		emptyCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, emptySec)
		Expect(bearerFilter.WithContext(emptyCtx)).To(HaveOccurred())

		// HttpSecurity with invalid config type
		badCfgSec := (&HttpSecurityBuilder{}).AddCustomSecurityFilter("bearerTokenAuthenticationFilter", "invalid-config-type").Build()
		badCfgCtx := context.WithValue(context.Background(), PrototypeContextParentInstance, badCfgSec)
		Expect(bearerFilter.WithContext(badCfgCtx)).To(HaveOccurred())

		// Injected dependencies in filter
		filterWithDeps := &BearerTokenAuthenticationFilter{}
		holderMock := &mockSecurityContextHolder{}
		mgrMock := &mockAuthManager{}
		filterWithDeps.SetInjectedDepsForTest(
			DefaultBearerTokenResolver{}.New(),
			mgrMock,
			holderMock,
		)
		validSec := (&HttpSecurityBuilder{}).AddCustomSecurityFilter("bearerTokenAuthenticationFilter", &BearerTokenConfig{}).Build()
		validCtx = context.WithValue(context.Background(), PrototypeContextParentInstance, validSec)
		Expect(filterWithDeps.WithContext(validCtx)).To(Succeed())

		// BearerTokenAuthenticationFilter.Authenticate with securityContextHolder populated
		reqURL, urlErr := url.Parse("https://resource.example.com/api/data")
		Expect(urlErr).NotTo(HaveOccurred())
		handlerWithAuth := NewMockSecurityHandler(HttpMethods.GET, reqURL)
		handlerWithAuth.SetHeader("Authorization", "Bearer "+tok.TokenValue)
		filterWithHolder := BearerTokenAuthenticationFilter{}.New(mgrMock, holderMock)
		authRes := filterWithHolder.Authenticate(handlerWithAuth)
		Expect(authRes).To(HaveOccurred())
		Expect(authRes.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))
		Expect(holderMock.GetContext().GetAuthentication()).NotTo(BeNil())

		// DefaultJwtAuthenticationConverter edge cases
		// 1. []string claim
		convSlice := NewDefaultJwtAuthenticationConverter().
			WithAuthoritiesClaims("groups").
			WithAuthorityPrefix("")
		jwtSlice := NewJwt("tok-slice", time.Time{}, time.Time{}, nil, map[string]any{
			"sub":    "alice",
			"groups": []string{"developers", "admins"},
		})
		authSlice, err := convSlice.Convert(jwtSlice)
		Expect(err).NotTo(HaveOccurred())
		Expect(authSlice.GetAuthorities()).To(ConsistOf(Authority("developers"), Authority("admins")))

		// 2. intermediate non-map in claim path
		convNested := NewDefaultJwtAuthenticationConverter().WithAuthoritiesClaims("user.roles")
		jwtNonMap := NewJwt("tok-nonmap", time.Time{}, time.Time{}, nil, map[string]any{
			"sub":  "bob",
			"user": "scalar-string-not-map",
		})
		authNonMap, err := convNested.Convert(jwtNonMap)
		Expect(err).NotTo(HaveOccurred())
		Expect(authNonMap.GetAuthorities()).To(BeEmpty())

		// 3. principalClaimName != "sub" but custom claim missing -> fallback to sub
		convPrincipal := NewDefaultJwtAuthenticationConverter().WithPrincipalClaimName("preferred_username")
		jwtNoCustom := NewJwt("tok-no-custom", time.Time{}, time.Time{}, nil, map[string]any{
			"sub": "fallback-sub",
		})
		authCustom, err := convPrincipal.Convert(jwtNoCustom)
		Expect(err).NotTo(HaveOccurred())
		Expect(authCustom.GetName()).To(Equal("fallback-sub"))
	})

	It("authenticates bearer token when only JwtDecoder is configured in BearerTokenConfig", func() {
		km, keyErr := RSAKeyManager{}.New(2048, "rs-cfg-key")
		Expect(keyErr).NotTo(HaveOccurred())
		encoder := NewDefaultJwtEncoder(km)
		decoder := NewNimbusJwtDecoder(km)

		now := time.Now()
		claims := NewJwtClaimsSet()
		claims.Subject = "jwt-cfg-user"
		claims.IssuedAt = now
		claims.ExpiresAt = now.Add(time.Hour)
		tok, encErr := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claims})
		Expect(encErr).NotTo(HaveOccurred())

		ctxHolder := &mockSecurityContextHolder{}
		filter := &BearerTokenAuthenticationFilter{}
		builder := &HttpSecurityBuilder{}
		cfg := &BearerTokenConfig{
			JwtDecoder:            decoder,
			SecurityContextHolder: ctxHolder,
		}
		builder.AddCustomSecurityFilter("bearerTokenAuthenticationFilter", cfg)
		sec := builder.Build()
		ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, sec)
		Expect(filter.WithContext(ctx)).To(Succeed())

		u, parseErr := url.Parse("https://api.example.com/data")
		Expect(parseErr).NotTo(HaveOccurred())
		h := NewMockSecurityHandler(HttpMethods.GET, u)
		h.SetHeader("Authorization", "Bearer "+tok.TokenValue)

		authResult := filter.Authenticate(h)
		Expect(authResult).To(HaveOccurred())
		Expect(authResult.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))
		Expect(ctxHolder.GetContext().GetAuthentication()).NotTo(BeNil())
		Expect(ctxHolder.GetContext().GetAuthentication().GetName()).To(Equal("jwt-cfg-user"))
	})
})

type failingJwtConverter struct{}

func (this *failingJwtConverter) Convert(_ *Jwt) (*JwtAuthenticationToken, Error) {
	return nil, NewError("ConversionError", "conversion failed")
}

type failingOpaqueConverter struct{}

func (this *failingOpaqueConverter) Convert(_ string, _ OAuth2AuthenticatedPrincipal) (Authentication, Error) {
	return nil, NewError("ConversionError", "opaque conversion failed")
}

type mockSimpleAuth struct{}

func (this *mockSimpleAuth) GetAuthorities() []GrantedAuthority { return nil }
func (this *mockSimpleAuth) GetCredentials() any                { return nil }
func (this *mockSimpleAuth) GetDetails() any                    { return nil }
func (this *mockSimpleAuth) GetPrincipal() any                  { return nil }
func (this *mockSimpleAuth) IsAuthenticated() bool              { return false }
func (this *mockSimpleAuth) SetAuthenticated(_ bool)            {}
func (this *mockSimpleAuth) GetName() string                    { return "simple" }

var _ = Describe("NimbusOpaqueTokenIntrospector", func() {
	It("successfully introspects an active token and returns OAuth2AuthenticatedPrincipal", func() {
		now := time.Now()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			Expect(r.Method).To(Equal(http.MethodPost))
			Expect(r.Header.Get("Content-Type")).To(Equal("application/x-www-form-urlencoded"))
			Expect(r.Header.Get("Accept")).To(Equal("application/json"))

			user, pass, ok := r.BasicAuth()
			Expect(ok).To(BeTrue())
			Expect(user).To(Equal("client-id-123"))
			Expect(pass).To(Equal("client-secret-xyz"))

			parseErr := r.ParseForm()
			Expect(parseErr).NotTo(HaveOccurred())
			Expect(r.Form.Get("token")).To(Equal("valid-opaque-tok"))
			Expect(r.Form.Get("token_type_hint")).To(Equal("access_token"))

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			resp := map[string]any{
				"active":    true,
				"sub":       "user-alice",
				"scope":     "read write admin",
				"exp":       now.Add(time.Hour).Unix(),
				"iat":       now.Add(-time.Minute).Unix(),
				"nbf":       now.Add(-time.Minute).Unix(),
				"aud":       "https://api.example.com",
				"client_id": "client-id-123",
			}
			encErr := json.NewEncoder(w).Encode(resp)
			Expect(encErr).NotTo(HaveOccurred())
		}))
		defer server.Close()

		introspector := NewNimbusOpaqueTokenIntrospector(server.URL, "client-id-123", "client-secret-xyz")
		principal, err := introspector.Introspect("valid-opaque-tok")
		Expect(err).NotTo(HaveOccurred())
		Expect(principal).NotTo(BeNil())
		Expect(principal.GetName()).To(Equal("user-alice"))

		var authNames []string
		for _, a := range principal.GetAuthorities() {
			authNames = append(authNames, a.Authority())
		}
		Expect(authNames).To(ConsistOf("SCOPE_read", "SCOPE_write", "SCOPE_admin"))
		Expect(principal.GetAttributes()).To(HaveKeyWithValue("aud", "https://api.example.com"))
	})

	It("fails introspection when token is inactive", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{"active": false})).To(Succeed())
		}))
		defer server.Close()

		introspector := NewDefaultOpaqueTokenIntrospector(server.URL, "client", "secret")
		principal, err := introspector.Introspect("inactive-token")
		Expect(err).To(HaveOccurred())
		Expect(principal).To(BeNil())
		Expect(err.Error()).To(ContainSubstring("not active"))
	})

	It("fails introspection when token is expired", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "expired-user",
				"exp":    time.Now().Add(-2 * time.Hour).Unix(),
			})).To(Succeed())
		}))
		defer server.Close()

		introspector := NewNimbusOpaqueTokenIntrospector(server.URL, "client", "secret").
			WithClockSkew(0)
		_, err := introspector.Introspect("expired-token")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("expired"))
	})

	It("fails introspection when token is not yet valid (nbf in future)", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "future-user",
				"nbf":    time.Now().Add(2 * time.Hour).Unix(),
			})).To(Succeed())
		}))
		defer server.Close()

		introspector := NewNimbusOpaqueTokenIntrospector(server.URL, "client", "secret").
			WithClockSkew(0)
		_, err := introspector.Introspect("future-token")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not yet valid"))
	})

	It("handles server errors, malformed responses, and validation edge cases", func() {
		// Empty URI
		emptyURI := NewNimbusOpaqueTokenIntrospector("", "client", "secret")
		_, err := emptyURI.Introspect("tok")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("introspectionURI must not be empty"))

		// Empty token
		validIntro := NewNimbusOpaqueTokenIntrospector("https://auth.example.com/introspect", "client", "secret")
		_, err = validIntro.Introspect("")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("token cannot be empty"))

		// HTTP status != 200
		errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer errServer.Close()
		introspectorErr := NewNimbusOpaqueTokenIntrospector(errServer.URL, "client", "secret")
		_, err = introspectorErr.Introspect("tok")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("returned status code 401"))

		// Invalid JSON
		badJSONServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, writeErr := w.Write([]byte("not valid json"))
			Expect(writeErr).NotTo(HaveOccurred())
		}))
		defer badJSONServer.Close()
		introspectorBadJSON := NewNimbusOpaqueTokenIntrospector(badJSONServer.URL, "client", "secret")
		_, err = introspectorBadJSON.Introspect("tok")
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to parse introspection response"))
	})

	It("supports custom principal claim name, authority prefix, custom HTTPClient, and timeout", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{
				"active":             true,
				"preferred_username": "custom_bob",
				"roles":              []any{"ADMIN", "OPERATOR"},
			})).To(Succeed())
		}))
		defer server.Close()

		introspector := NewNimbusOpaqueTokenIntrospector(server.URL, "client", "secret").
			WithHTTPClient(server.Client()).
			WithPrincipalClaimName("preferred_username").
			WithAuthoritiesClaims("roles").
			WithAuthorityPrefix("ROLE_").
			WithTimeout(5 * time.Second)

		principal, err := introspector.Introspect("tok")
		Expect(err).NotTo(HaveOccurred())
		Expect(principal.GetName()).To(Equal("custom_bob"))

		var auths []string
		for _, a := range principal.GetAuthorities() {
			auths = append(auths, a.Authority())
		}
		Expect(auths).To(ConsistOf("ROLE_ADMIN", "ROLE_OPERATOR"))
	})

	It("falls back to username and client_id when sub is absent", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{
				"active":    true,
				"client_id": "service-app",
			})).To(Succeed())
		}))
		defer server.Close()

		introspector := NewNimbusOpaqueTokenIntrospector(server.URL, "c", "s")
		principal, err := introspector.Introspect("tok")
		Expect(err).NotTo(HaveOccurred())
		Expect(principal.GetName()).To(Equal("service-app"))
	})
})

var _ = Describe("DefaultOpaqueTokenAuthenticationConverter", func() {
	It("converts principal and token into BearerTokenAuthentication", func() {
		now := time.Now()
		attrs := map[string]any{
			"sub":   "charlie",
			"scope": "read write",
			"exp":   float64(now.Add(time.Hour).Unix()),
			"iat":   float64(now.Unix()),
		}
		authorities := []GrantedAuthority{Authority("SCOPE_read"), Authority("SCOPE_write")}
		principal := NewDefaultOAuth2AuthenticatedPrincipal("charlie", attrs, authorities)

		conv := NewDefaultOpaqueTokenAuthenticationConverter()
		auth, err := conv.Convert("raw-opaque-token", principal)
		Expect(err).NotTo(HaveOccurred())
		Expect(auth).NotTo(BeNil())
		Expect(auth.IsAuthenticated()).To(BeTrue())
		Expect(auth.GetName()).To(Equal("charlie"))
		Expect(auth.GetCredentials()).To(Equal("raw-opaque-token"))

		bearerAuth, ok := auth.(*BearerTokenAuthentication)
		Expect(ok).To(BeTrue())
		Expect(bearerAuth.GetToken()).NotTo(BeNil())
		Expect(bearerAuth.GetToken().TokenValue).To(Equal("raw-opaque-token"))
		Expect(bearerAuth.GetAttributes()).To(HaveKeyWithValue("sub", "charlie"))
	})

	It("rejects nil principal", func() {
		conv := DefaultOpaqueTokenAuthenticationConverter{}.New().WithAuthorityPrefix("ROLE_")
		_, err := conv.Convert("raw", nil)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("OpaqueTokenAuthenticationProvider", func() {
	It("authenticates a valid Bearer token and returns BearerTokenAuthentication", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "david",
				"scope":  "profile email",
			})).To(Succeed())
		}))
		defer server.Close()

		introspector := NewNimbusOpaqueTokenIntrospector(server.URL, "client-app", "client-secret")
		provider := NewOpaqueTokenAuthenticationProvider(introspector)

		bearerTok := NewBearerTokenAuthenticationToken("david-token")
		Expect(provider.Supports(bearerTok)).To(BeTrue())

		auth, authEx := provider.Authenticate(bearerTok)
		Expect(authEx).NotTo(HaveOccurred())
		Expect(auth.IsAuthenticated()).To(BeTrue())
		Expect(auth.GetName()).To(Equal("david"))

		var names []string
		for _, a := range auth.GetAuthorities() {
			names = append(names, a.Authority())
		}
		Expect(names).To(ConsistOf("SCOPE_profile", "SCOPE_email"))
	})

	It("fails authentication when token is invalid or inactive", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{"active": false})).To(Succeed())
		}))
		defer server.Close()

		introspector := NewNimbusOpaqueTokenIntrospector(server.URL, "c", "s")
		provider := OpaqueTokenAuthenticationProvider{}.New(introspector)

		bearerTok := NewBearerTokenAuthenticationToken("inactive-token")
		_, authEx := provider.Authenticate(bearerTok)
		Expect(authEx).To(HaveOccurred())
	})

	It("handles edge cases: non-bearer auth, nil introspector, and failing converter", func() {
		p := NewOpaqueTokenAuthenticationProvider(nil)

		// Non-bearer token
		_, err := p.Authenticate(&mockSimpleAuth{})
		Expect(err).To(HaveOccurred())

		// Nil introspector
		_, err = p.Authenticate(NewBearerTokenAuthenticationToken("tok"))
		Expect(err).To(HaveOccurred())

		// DI test and PostConstruct
		mockIntro := NewNimbusOpaqueTokenIntrospector("https://auth.example.com", "c", "s")
		pDI := &OpaqueTokenAuthenticationProvider{}
		pDI.SetInjectedIntrospectorForTest(mockIntro)
		pDI.SetInjectedConverterForTest(NewDefaultOpaqueTokenAuthenticationConverter())
		Expect(pDI.PostConstruct()).To(Succeed())
		Expect(pDI.GetIntrospectorForTest()).To(Equal(mockIntro))
		Expect(pDI.GetConverterForTest()).NotTo(BeNil())

		// Failing converter
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "test"})).To(Succeed())
		}))
		defer server.Close()

		failingProv := NewOpaqueTokenAuthenticationProvider(NewNimbusOpaqueTokenIntrospector(server.URL, "c", "s")).
			WithConverter(&failingOpaqueConverter{})
		_, err = failingProv.Authenticate(NewBearerTokenAuthenticationToken("tok"))
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("BearerTokenAuthenticationFilter with Opaque Token", func() {
	It("authenticates bearer token when only OpaqueTokenIntrospector is configured in BearerTokenConfig", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "opaque-cfg-user",
				"scope":  "read",
			})).To(Succeed())
		}))
		defer server.Close()

		introspector := NewNimbusOpaqueTokenIntrospector(server.URL, "rs-client", "rs-secret")
		ctxHolder := &mockSecurityContextHolder{}
		filter := &BearerTokenAuthenticationFilter{}
		builder := &HttpSecurityBuilder{}
		cfg := &BearerTokenConfig{
			OpaqueTokenIntrospector: introspector,
			SecurityContextHolder:   ctxHolder,
		}
		builder.AddCustomSecurityFilter("bearerTokenAuthenticationFilter", cfg)
		sec := builder.Build()
		ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, sec)
		Expect(filter.WithContext(ctx)).To(Succeed())

		u, err := url.Parse("https://api.example.com/opaque-data")
		Expect(err).NotTo(HaveOccurred())
		h := NewMockSecurityHandler(HttpMethods.GET, u)
		h.SetHeader("Authorization", "Bearer my-opaque-token")

		authResult := filter.Authenticate(h)
		Expect(authResult).To(HaveOccurred())
		Expect(authResult.Action()).To(Equal(DefaultSecurityFilterAction{}.New().NEXT.Name()))
		Expect(ctxHolder.GetContext().GetAuthentication()).NotTo(BeNil())
		Expect(ctxHolder.GetContext().GetAuthentication().GetName()).To(Equal("opaque-cfg-user"))

		// DI Injection into BearerTokenAuthenticationFilter
		filterDI := &BearerTokenAuthenticationFilter{}
		filterDI.SetInjectedIntrospectorForTest(introspector)
		filterDI.SetInjectedOpaqueConverterForTest(NewDefaultOpaqueTokenAuthenticationConverter())
		secDI := (&HttpSecurityBuilder{}).AddCustomSecurityFilter("bearerTokenAuthenticationFilter", &BearerTokenConfig{}).Build()
		ctxDI := context.WithValue(context.Background(), PrototypeContextParentInstance, secDI)
		Expect(filterDI.WithContext(ctxDI)).To(Succeed())
	})

	It("issues 401 when opaque token is inactive or rejected", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			Expect(json.NewEncoder(w).Encode(map[string]any{"active": false})).To(Succeed())
		}))
		defer server.Close()

		introspector := NewNimbusOpaqueTokenIntrospector(server.URL, "rs", "sec")
		ctxHolder := &mockSecurityContextHolder{}
		filter := (&BearerTokenAuthenticationFilter{}).
			WithOpaqueTokenIntrospector(introspector)

		builder := &HttpSecurityBuilder{}
		cfg := &BearerTokenConfig{
			OpaqueTokenIntrospector: introspector,
			SecurityContextHolder:   ctxHolder,
		}
		builder.AddCustomSecurityFilter("bearerTokenAuthenticationFilter", cfg)
		sec := builder.Build()
		ctx := context.WithValue(context.Background(), PrototypeContextParentInstance, sec)
		Expect(filter.WithContext(ctx)).To(Succeed())

		u, err := url.Parse("https://api.example.com/protected")
		Expect(err).NotTo(HaveOccurred())
		h := NewMockSecurityHandler(HttpMethods.GET, u)
		h.SetHeader("Authorization", "Bearer invalid-token")

		authResult := filter.Authenticate(h)
		Expect(authResult).To(HaveOccurred())
		defaultEx, ok := authResult.(*DefaultSecurityFilterChainException)
		Expect(ok).To(BeTrue())
		Expect(defaultEx.Status()).To(Equal(401))
		Expect(h.Header("WWW-Authenticate")).To(ContainSubstring(`error="invalid_token"`))
	})
})
