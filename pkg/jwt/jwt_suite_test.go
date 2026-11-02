package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays/pkg/lang"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestJwt(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "OAuth2 JWT Suite")
}

var _ = Describe("RSAKeyManager and NimbusJwtDecoder/Encoder", func() {
	It("generates an RSA key, encodes a JWT, and decodes it", func() {
		km, err := RSAKeyManager{}.New(2048, "test-key-1")
		Expect(err).NotTo(HaveOccurred())

		jwkSet, err := km.GetJWKSet()
		Expect(err).NotTo(HaveOccurred())
		Expect(jwkSet.Keys).To(HaveLen(1))
		Expect(jwkSet.Keys[0].Kid).To(Equal("test-key-1"))

		encoder := DefaultJwtEncoder{}.New(km)

		now := time.Now()
		claimsSet := JwtClaimsSet{}.New()
		claimsSet.Issuer = "https://auth.beamfoundry.com"
		claimsSet.Subject = "user-12345"
		claimsSet.Audience = []string{"api-orders"}
		claimsSet.IssuedAt = now
		claimsSet.ExpiresAt = now.Add(1 * time.Hour)
		claimsSet.Claims["scope"] = "read write"

		token, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claimsSet})
		Expect(err).NotTo(HaveOccurred())
		Expect(token.TokenValue).NotTo(BeEmpty())

		decoder := NimbusJwtDecoder{}.New(km).
			WithIssuer("https://auth.beamfoundry.com").
			WithAudience("api-orders")

		decoded, err := decoder.Decode(token.TokenValue)
		Expect(err).NotTo(HaveOccurred())
		Expect(decoded.Subject()).To(Equal("user-12345"))
		Expect(decoded.Issuer()).To(Equal("https://auth.beamfoundry.com"))
		Expect(decoded.Audience()).To(ConsistOf("api-orders"))
		Expect(decoded.Claims).To(HaveKeyWithValue("scope", "read write"))
	})

	It("fails decoding when issuer does not match", func() {
		km, err := RSAKeyManager{}.New(2048, "test-key-2")
		Expect(err).NotTo(HaveOccurred())

		encoder := DefaultJwtEncoder{}.New(km)
		claimsSet := JwtClaimsSet{}.New()
		claimsSet.Issuer = "https://attacker.example.com"
		claimsSet.Subject = "malicious-user"
		claimsSet.ExpiresAt = time.Now().Add(10 * time.Minute)

		tok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claimsSet})
		Expect(err).NotTo(HaveOccurred())

		decoder := NimbusJwtDecoder{}.New(km).WithIssuer("https://auth.beamfoundry.com")
		_, err = decoder.Decode(tok.TokenValue)
		Expect(err).To(HaveOccurred())
	})
})

var _ = Describe("JwxJwtEncoder & JwxJwtDecoder", func() {
	Context("with ECDSA (ES256)", func() {
		It("signs with ES256 private key and verifies with public JWK set", func() {
			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			encoder := JwxJwtEncoder{}.New(privKey, jwa.ES256(), "key-es256-1")

			now := time.Now()
			claims := JwtClaimsSet{}.New()
			claims.Issuer = "https://auth.example.com"
			claims.Subject = "ecdsa-user"
			claims.Audience = []string{"api"}
			claims.IssuedAt = now
			claims.ExpiresAt = now.Add(1 * time.Hour)
			claims.Claims["role"] = "admin"

			tok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claims})
			Expect(err).NotTo(HaveOccurred())
			Expect(tok.TokenValue).NotTo(BeEmpty())

			pubKey, err := jwk.Import(&privKey.PublicKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(pubKey.Set(jwk.KeyIDKey, "key-es256-1")).To(Succeed())
			Expect(pubKey.Set(jwk.AlgorithmKey, jwa.ES256())).To(Succeed())

			set := jwk.NewSet()
			Expect(set.AddKey(pubKey)).To(Succeed())

			decoder := JwxJwtDecoder{}.NewWithKeySet(set).
				WithIssuer("https://auth.example.com").
				WithAudience("api")

			decoded, err := decoder.Decode(tok.TokenValue)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded.Subject()).To(Equal("ecdsa-user"))
			Expect(decoded.Claims).To(HaveKeyWithValue("role", "admin"))

			// Issuer mismatch
			decoderWrongIss := JwxJwtDecoder{}.NewWithKeySet(set).WithIssuer("https://wrong-issuer.com")
			_, err = decoderWrongIss.Decode(tok.TokenValue)
			Expect(err).To(HaveOccurred())

			// Audience mismatch
			decoderWrongAud := JwxJwtDecoder{}.NewWithKeySet(set).WithAudience("wrong-audience")
			_, err = decoderWrongAud.Decode(tok.TokenValue)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("with Ed25519 (EdDSA)", func() {
		It("signs with Ed25519 private key and verifies with public JWK set", func() {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			Expect(err).NotTo(HaveOccurred())

			encoder := JwxJwtEncoder{}.New(priv, jwa.EdDSA(), "key-ed25519-1")

			claims := JwtClaimsSet{}.New()
			claims.Issuer = "https://auth.example.com"
			claims.Subject = "eddsa-user"
			claims.ExpiresAt = time.Now().Add(10 * time.Minute)

			tok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claims})
			Expect(err).NotTo(HaveOccurred())

			pubJWK, err := jwk.Import(pub)
			Expect(err).NotTo(HaveOccurred())
			Expect(pubJWK.Set(jwk.KeyIDKey, "key-ed25519-1")).To(Succeed())
			Expect(pubJWK.Set(jwk.AlgorithmKey, jwa.EdDSA())).To(Succeed())

			set := jwk.NewSet()
			Expect(set.AddKey(pubJWK)).To(Succeed())

			decoder := JwxJwtDecoder{}.NewWithKeySet(set).WithIssuer("https://auth.example.com")
			decoded, err := decoder.Decode(tok.TokenValue)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded.Subject()).To(Equal("eddsa-user"))
		})
	})

	Context("with RSA-PSS (PS256)", func() {
		It("signs with RSA private key using PS256 and verifies with public JWK set", func() {
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			encoder := JwxJwtEncoder{}.New(priv, jwa.PS256(), "key-ps256-1")

			claims := JwtClaimsSet{}.New()
			claims.Subject = "pss-user"
			claims.ExpiresAt = time.Now().Add(10 * time.Minute)

			tok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claims})
			Expect(err).NotTo(HaveOccurred())

			pubJWK, err := jwk.Import(&priv.PublicKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(pubJWK.Set(jwk.KeyIDKey, "key-ps256-1")).To(Succeed())
			Expect(pubJWK.Set(jwk.AlgorithmKey, jwa.PS256())).To(Succeed())

			set := jwk.NewSet()
			Expect(set.AddKey(pubJWK)).To(Succeed())

			decoder := JwxJwtDecoder{}.NewWithKeySet(set)
			decoded, err := decoder.Decode(tok.TokenValue)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded.Subject()).To(Equal("pss-user"))
		})
	})

	Context("constructors, options, skew and validation failures", func() {
		It("tests NewRSAKeyManager, NewDefaultJwtEncoder, NewNimbusJwtDecoder, WithClockSkew and KeyID", func() {
			km, err := NewRSAKeyManager(2048, "rsa-test-key")
			Expect(err).NotTo(HaveOccurred())
			Expect(km).NotTo(BeNil())

			encoder := NewDefaultJwtEncoder(km)
			claimsSet := NewJwtClaimsSet()
			claimsSet.Issuer = "https://auth.example.com"
			claimsSet.Subject = "bob"
			claimsSet.Audience = []string{"api-service"}
			claimsSet.IssuedAt = time.Now().Add(-10 * time.Minute)
			claimsSet.ExpiresAt = time.Now().Add(-5 * time.Second) // expired 5s ago

			tok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claimsSet})
			Expect(err).NotTo(HaveOccurred())
			Expect(tok.KeyID()).To(Equal("rsa-test-key"))

			// Decoder with 0 skew should fail on expired token
			decoderNoSkew := NewNimbusJwtDecoder(km).
				WithIssuer("https://auth.example.com").
				WithAudience("api-service").
				WithClockSkew(0)
			_, err = decoderNoSkew.Decode(tok.TokenValue)
			Expect(err).To(HaveOccurred())

			// Decoder with 60s skew should succeed
			decoderWithSkew := NewNimbusJwtDecoder(km).
				WithIssuer("https://auth.example.com").
				WithAudience("api-service").
				WithClockSkew(60 * time.Second)
			decoded, err := decoderWithSkew.Decode(tok.TokenValue)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded.Subject()).To(Equal("bob"))
			Expect(decoded.KeyID()).To(Equal("rsa-test-key"))

			// Audience mismatch fails
			decoderWrongAud := NewNimbusJwtDecoder(km).
				WithIssuer("https://auth.example.com").
				WithAudience("wrong-audience")
			_, err = decoderWrongAud.Decode(tok.TokenValue)
			Expect(err).To(HaveOccurred())
		})

		It("tests ParseRSAPublicKeyFromJWK with valid and invalid JWKs", func() {
			km, err := NewRSAKeyManager(2048, "rsa-jwk-key")
			Expect(err).NotTo(HaveOccurred())
			jwkSet, err := km.GetJWKSet()
			Expect(err).NotTo(HaveOccurred())
			Expect(jwkSet.Keys).NotTo(BeEmpty())

			validJWK := &jwkSet.Keys[0]
			pubKey, err := ParseRSAPublicKeyFromJWK(validJWK)
			Expect(err).NotTo(HaveOccurred())
			Expect(pubKey).NotTo(BeNil())
			Expect(pubKey.N).NotTo(BeNil())

			// Invalid N base64
			_, err = ParseRSAPublicKeyFromJWK(&JWK{N: "!!!invalid", E: validJWK.E})
			Expect(err).To(HaveOccurred())

			// Invalid E base64
			_, err = ParseRSAPublicKeyFromJWK(&JWK{N: validJWK.N, E: "!!!invalid"})
			Expect(err).To(HaveOccurred())
		})

		It("tests JwxJwtDecoder with remote JWKS HTTP server, skew and audience mismatch", func() {
			privKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).NotTo(HaveOccurred())

			pubJWK, err := jwk.Import(&privKey.PublicKey)
			Expect(err).NotTo(HaveOccurred())
			Expect(pubJWK.Set(jwk.KeyIDKey, "remote-key-1")).To(Succeed())
			Expect(pubJWK.Set(jwk.AlgorithmKey, jwa.RS256())).To(Succeed())

			set := jwk.NewSet()
			Expect(set.AddKey(pubJWK)).To(Succeed())

			jsonBytes, err := json.Marshal(set)
			Expect(err).NotTo(HaveOccurred())

			var fetchCount atomic.Int64
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fetchCount.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, writeErr := w.Write(jsonBytes)
				Expect(writeErr).NotTo(HaveOccurred())
			}))
			defer ts.Close()

			encoder := NewJwxJwtEncoder(privKey, jwa.RS256(), "remote-key-1")
			claims := NewJwtClaimsSet()
			claims.Issuer = "https://remote.example.com"
			claims.Subject = "remote-user"
			claims.Audience = []string{"remote-audience"}
			claims.ExpiresAt = time.Now().Add(-5 * time.Second) // expired 5s ago

			tok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claims})
			Expect(err).NotTo(HaveOccurred())

			// Remote decoder with clock skew accepts token
			decoder := NewJwxJwtDecoderWithRemoteJWKS(ts.URL).
				WithIssuer("https://remote.example.com").
				WithAudience("remote-audience").
				WithClockSkew(60 * time.Second)

			decoded, err := decoder.Decode(tok.TokenValue)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded.Subject()).To(Equal("remote-user"))

			initialFetches := fetchCount.Load()
			// Second decode reuses cached key set without additional HTTP fetch
			decoded2, err := decoder.Decode(tok.TokenValue)
			Expect(err).NotTo(HaveOccurred())
			Expect(decoded2.Subject()).To(Equal("remote-user"))
			Expect(fetchCount.Load()).To(Equal(initialFetches))

			// Concurrent decodes coalesce initial fetches
			var concurrentFetches atomic.Int64
			tsConcurrent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				concurrentFetches.Add(1)
				time.Sleep(300 * time.Millisecond) // simulate network latency exceeding Ready timeout
				w.Header().Set("Content-Type", "application/json")
				_, writeErr := w.Write(jsonBytes)
				Expect(writeErr).NotTo(HaveOccurred())
			}))
			defer tsConcurrent.Close()

			concurrentDecoder := NewJwxJwtDecoderWithRemoteJWKS(tsConcurrent.URL).
				WithIssuer("https://remote.example.com").
				WithAudience("remote-audience").
				WithClockSkew(60 * time.Second)

			var wg sync.WaitGroup
			numGoroutines := 10
			wg.Add(numGoroutines)
			for i := 0; i < numGoroutines; i++ {
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					dec, decErr := concurrentDecoder.Decode(tok.TokenValue)
					Expect(decErr).NotTo(HaveOccurred())
					Expect(dec.Subject()).To(Equal("remote-user"))
				}()
			}
			wg.Wait()
			Expect(concurrentFetches.Load()).To(BeNumerically("<=", 2))

			// Test audience mismatch
			decoderWrongAud := NewJwxJwtDecoderWithKeySet(set).
				WithIssuer("https://remote.example.com").
				WithAudience("wrong-remote-audience")
			_, err = decoderWrongAud.Decode(tok.TokenValue)
			Expect(err).To(HaveOccurred())

			// Test issuer mismatch
			decoderWrongIss := NewJwxJwtDecoderWithKeySet(set).
				WithIssuer("https://wrong-issuer.com").
				WithAudience("remote-audience")
			_, err = decoderWrongIss.Decode(tok.TokenValue)
			Expect(err).To(HaveOccurred())

			// Test missing expiration claim rejected even when no other optional settings configured
			claimsNoExp := NewJwtClaimsSet()
			claimsNoExp.Issuer = "https://remote.example.com"
			claimsNoExp.Subject = "remote-user"
			tokNoExp, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claimsNoExp})
			Expect(err).NotTo(HaveOccurred())
			decoderDefault := NewJwxJwtDecoderWithKeySet(set)
			_, err = decoderDefault.Decode(tokNoExp.TokenValue)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("jwt validation failed"))
		})

		It("tests NimbusJwtDecoder error handling on malformed token and bad signature", func() {
			km, err := NewRSAKeyManager(2048, "rsa-err-key")
			Expect(err).NotTo(HaveOccurred())
			decoder := NewNimbusJwtDecoder(km)

			// Malformed (not 3 parts)
			_, err = decoder.Decode("invalid-part1.invalid-part2")
			Expect(err).To(HaveOccurred())

			// Tampered signature
			encoder := NewDefaultJwtEncoder(km)
			tok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: NewJwtClaimsSet()})
			Expect(err).NotTo(HaveOccurred())

			tampered := tok.TokenValue[:len(tok.TokenValue)-5] + "XXXXX"
			_, err = decoder.Decode(tampered)
			Expect(err).To(HaveOccurred())
		})

		It("tests ParseUnverified errors and Jwt claim getters", func() {
			// Malformed (not 3 parts)
			_, _, err := ParseUnverified("only.two")
			Expect(err).To(HaveOccurred())

			// Invalid header base64
			_, _, err = ParseUnverified("!!!.eyJzdWIiOiIxIn0.")
			Expect(err).To(HaveOccurred())

			// Invalid claims base64
			_, _, err = ParseUnverified("eyJhbGciOiJub25lIn0.!!!.")
			Expect(err).To(HaveOccurred())

			// Invalid header JSON
			badHdr := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
			_, _, err = ParseUnverified(badHdr + ".eyJzdWIiOiIxIn0.")
			Expect(err).To(HaveOccurred())

			// Invalid claims JSON
			badClaims := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
			_, _, err = ParseUnverified("eyJhbGciOiJub25lIn0." + badClaims + ".")
			Expect(err).To(HaveOccurred())

			// Jwt getters: Subject, Issuer, Audience
			jwtEmpty := NewJwt("raw", time.Time{}, time.Time{}, map[string]any{}, map[string]any{})
			Expect(jwtEmpty.Subject()).To(BeEmpty())
			Expect(jwtEmpty.Issuer()).To(BeEmpty())
			Expect(jwtEmpty.Audience()).To(BeNil())

			// Audience as string
			jwtAudStr := NewJwt("raw", time.Time{}, time.Time{}, map[string]any{}, map[string]any{"aud": "single-aud"})
			Expect(jwtAudStr.Audience()).To(Equal([]string{"single-aud"}))

			// Audience as []string
			jwtAudSlice := NewJwt("raw", time.Time{}, time.Time{}, map[string]any{}, map[string]any{"aud": []string{"aud1", "aud2"}})
			Expect(jwtAudSlice.Audience()).To(Equal([]string{"aud1", "aud2"}))

			// Audience as []any
			jwtAudAny := NewJwt("raw", time.Time{}, time.Time{}, map[string]any{}, map[string]any{"aud": []any{"audA", "audB"}})
			Expect(jwtAudAny.Audience()).To(Equal([]string{"audA", "audB"}))

			// KeyID on empty vs set
			Expect(jwtEmpty.KeyID()).To(BeEmpty())
		})

		It("tests NimbusJwtDecoder claim validations and HMAC support", func() {
			km, err := NewRSAKeyManager(2048, "rsa-claim-key")
			Expect(err).NotTo(HaveOccurred())
			encoder := NewDefaultJwtEncoder(km)

			// Expired token
			expClaims := NewJwtClaimsSet()
			expClaims.ExpiresAt = time.Now().Add(-1 * time.Hour)
			expTok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: expClaims})
			Expect(err).NotTo(HaveOccurred())
			_, err = NewNimbusJwtDecoder(km).Decode(expTok.TokenValue)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("expired"))

			// Not active yet (nbf in future)
			nbfClaims := NewJwtClaimsSet()
			nbfClaims.NotBefore = time.Now().Add(1 * time.Hour)
			nbfTok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: nbfClaims})
			Expect(err).NotTo(HaveOccurred())
			_, err = NewNimbusJwtDecoder(km).Decode(nbfTok.TokenValue)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("not yet valid"))

			// Issuer mismatch
			issClaims := NewJwtClaimsSet()
			issClaims.Issuer = "https://actual-iss.com"
			issTok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: issClaims})
			Expect(err).NotTo(HaveOccurred())
			_, err = NewNimbusJwtDecoder(km).WithIssuer("https://expected-iss.com").Decode(issTok.TokenValue)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid issuer"))

			// Audience mismatch
			audClaims := NewJwtClaimsSet()
			audClaims.Audience = []string{"client-app"}
			audTok, err := encoder.Encode(&JwtEncoderParameters{ClaimsSet: audClaims})
			Expect(err).NotTo(HaveOccurred())
			_, err = NewNimbusJwtDecoder(km).WithAudience("wrong-app").Decode(audTok.TokenValue)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid audience"))

			// Algorithm mismatch
			diffAlgSource := &testMockJWKSource{secret: []byte("hmac-secret-32-bytes-long-key!!"), alg: "HS256"}
			_, err = NewNimbusJwtDecoder(diffAlgSource).Decode(audTok.TokenValue)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("algorithm mismatch"))

			// HS256 signing and verification
			hmacSource := &testMockJWKSource{secret: []byte("hmac-secret-32-bytes-long-key!!"), alg: "HS256"}
			rawHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"hmac-1"}`))
			rawClaims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"hmac-user"}`))
			mac := hmac.New(sha256.New, []byte("hmac-secret-32-bytes-long-key!!"))
			Expect(mac.Write([]byte(rawHeader + "." + rawClaims))).To(Equal(len(rawHeader + "." + rawClaims)))
			rawSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
			hmacToken := rawHeader + "." + rawClaims + "." + rawSig

			decodedHmac, err := NewNimbusJwtDecoder(hmacSource).Decode(hmacToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(decodedHmac.Subject()).To(Equal("hmac-user"))

			// HS256 bad signature
			badHmacToken := rawHeader + "." + rawClaims + "." + base64.RawURLEncoding.EncodeToString([]byte("bad-sig-bytes-length-here"))
			_, err = NewNimbusJwtDecoder(hmacSource).Decode(badHmacToken)
			Expect(err).To(HaveOccurred())

			// HS256 with invalid key type
			invalidSecretSource := &testMockJWKSource{secret: 12345, alg: "HS256"}
			_, err = NewNimbusJwtDecoder(invalidSecretSource).Decode(hmacToken)
			Expect(err).To(HaveOccurred())

			// Unsupported algorithm
			unsupportedHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES512","typ":"JWT","kid":"hmac-1"}`))
			unsupportedTok := unsupportedHeader + "." + rawClaims + "." + rawSig
			unsupportedSource := &testMockJWKSource{secret: []byte("secret"), alg: "ES512"}
			_, err = NewNimbusJwtDecoder(unsupportedSource).Decode(unsupportedTok)
			Expect(err).To(HaveOccurred())

			// JwxJwtEncoder with invalid key
			invalidJwxEncoder := NewJwxJwtEncoder("not-a-valid-key", jwa.RS256(), "k1")
			_, err = invalidJwxEncoder.Encode(&JwtEncoderParameters{ClaimsSet: NewJwtClaimsSet()})
			Expect(err).To(HaveOccurred())

			// JwxJwtDecoder remote JWKS fetch error
			invalidJwxDecoder := NewJwxJwtDecoderWithRemoteJWKS("http://127.0.0.1:54321/bad-jwks")
			_, err = invalidJwxDecoder.Decode(hmacToken)
			Expect(err).To(HaveOccurred())

			// RSAKeyManager defaults for bits and kid
			kmDefault, kmErr := RSAKeyManager{}.New(1024, "")
			Expect(kmErr).NotTo(HaveOccurred())
			jwkSetDef, kmErr := kmDefault.GetJWKSet()
			Expect(kmErr).NotTo(HaveOccurred())
			Expect(jwkSetDef.Keys[0].Kid).To(HavePrefix("k-"))

			// RSAKeyManager UnknownKeyIdError
			_, _, unknownKeyErr := kmDefault.GetVerificationKey("non-existent-kid")
			Expect(unknownKeyErr).To(HaveOccurred())

			// DefaultJwtEncoder with NotBefore, IssuedAt, JWTID
			fullClaims := NewJwtClaimsSet()
			fullClaims.Issuer = "https://auth.example.com"
			fullClaims.Subject = "sub-123"
			fullClaims.NotBefore = time.Now().Add(-1 * time.Minute)
			fullClaims.IssuedAt = time.Now()
			fullClaims.JWTID = "jwt-unique-id"
			fullClaims.ExpiresAt = time.Now().Add(10 * time.Minute)
			fullTok, fullErr := NewDefaultJwtEncoder(kmDefault).Encode(&JwtEncoderParameters{ClaimsSet: fullClaims})
			Expect(fullErr).NotTo(HaveOccurred())
			Expect(fullTok.Claims).To(HaveKeyWithValue("jti", "jwt-unique-id"))

			// DefaultJwtEncoder error cases
			// RS256 with invalid private key type
			invalidRsaEncoder := NewDefaultJwtEncoder(&testMockJWKSource{secret: "not-rsa-key", alg: AlgRS256})
			_, encErr := invalidRsaEncoder.Encode(&JwtEncoderParameters{ClaimsSet: fullClaims})
			Expect(encErr).To(HaveOccurred())

			// HS256 with invalid secret key type
			invalidHsEncoder := NewDefaultJwtEncoder(&testMockJWKSource{secret: 12345, alg: "HS256"})
			_, encErr = invalidHsEncoder.Encode(&JwtEncoderParameters{ClaimsSet: fullClaims})
			Expect(encErr).To(HaveOccurred())

			// Unsupported signing algorithm
			unsupportedEncoder := NewDefaultJwtEncoder(&testMockJWKSource{secret: []byte("sec"), alg: "UNSUPPORTED"})
			_, encErr = unsupportedEncoder.Encode(&JwtEncoderParameters{ClaimsSet: fullClaims})
			Expect(encErr).To(HaveOccurred())

			// NimbusJwtDecoder error cases
			// Malformed JWT format
			_, decErr := NewNimbusJwtDecoder(kmDefault).Decode("not-a-jwt")
			Expect(decErr).To(HaveOccurred())

			// Invalid signature base64
			_, decErr = NewNimbusJwtDecoder(kmDefault).Decode(rawHeader + "." + rawClaims + ".invalid!base64!chars")
			Expect(decErr).To(HaveOccurred())

			// RS256 with invalid public key type
			//nolint:gosec // mock test key
			invalidPubSource := &testMockJWKSource{secret: "not-rsa-public-key", alg: AlgRS256}
			_, decErr = NewNimbusJwtDecoder(invalidPubSource).Decode(fullTok.TokenValue)
			Expect(decErr).To(HaveOccurred())
		})
	})
})

type testMockJWKSource struct {
	secret any
	alg    string
}

func (this *testMockJWKSource) GetJWKSet() (*JWKSet, Error) {
	return &JWKSet{}, nil
}

//nolint:revive // JWKSource interface requires 4 return values
func (this *testMockJWKSource) GetSigningKey() (kid string, privateKey any, alg string, err Error) {
	return "hmac-1", this.secret, this.alg, nil
}

func (this *testMockJWKSource) GetVerificationKey(_ string) (publicKey any, alg string, err Error) {
	return this.secret, this.alg, nil
}
