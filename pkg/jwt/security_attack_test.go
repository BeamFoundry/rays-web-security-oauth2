package jwt_test

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
	. "github.com/BeamFoundry/rays/pkg/lang"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OAuth2 & JWT Security Attack Vectors", func() {
	var (
		km      *RSAKeyManager
		decoder *NimbusJwtDecoder
	)

	BeforeEach(func() {
		var err Error
		km, err = RSAKeyManager{}.New(2048, "security-test-key")
		Expect(err).NotTo(HaveOccurred())
		decoder = NimbusJwtDecoder{}.New(km).WithClockSkew(5 * time.Second)
	})

	Context("Algorithm Confusion & Substitution Attacks", func() {
		It("rejects tokens using alg=none in lowercase, uppercase, and mixed case", func() {
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"victim","role":"admin"}`))

			for _, noneAlg := range []string{"none", "NONE", "None", "nOnE"} {
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + noneAlg + `","typ":"JWT"}`))
				unsignedToken := header + "." + payload + "."

				_, err := decoder.Decode(unsignedToken)
				Expect(err).To(HaveOccurred(), "Must reject alg="+noneAlg)
			}
		})

		It("rejects tokens with missing or empty alg parameter", func() {
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"victim"}`))
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
			token := header + "." + payload + "."

			_, err := decoder.Decode(token)
			Expect(err).To(HaveOccurred())
		})

		It("prevents RSA-to-HMAC Key Confusion attack", func() {
			// Attacker attempts to sign with HS256 using the RSA public key's modulus bytes as HMAC secret
			jwkSet, err := km.GetJWKSet()
			Expect(err).NotTo(HaveOccurred())
			Expect(jwkSet.Keys).NotTo(BeEmpty())

			fakeSecret := []byte(jwkSet.Keys[0].N)

			headerJSON, errH := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT", "kid": "security-test-key"})
			Expect(errH).NotTo(HaveOccurred())
			claimsJSON, errC := json.Marshal(map[string]any{"sub": "attacker-escalated-role", "role": "admin"})
			Expect(errC).NotTo(HaveOccurred())

			signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)

			mac := hmac.New(sha256.New, fakeSecret)
			_, writeErr := mac.Write([]byte(signingInput))
			Expect(writeErr).NotTo(HaveOccurred())
			forgedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

			forgedToken := signingInput + "." + forgedSig

			// Must be rejected because the key manager expects RS256, not HS256
			_, decodeErr := decoder.Decode(forgedToken)
			Expect(decodeErr).To(HaveOccurred())
			Expect(decodeErr.Name()).To(Equal("AlgorithmMismatchError"))
		})
	})

	Context("Signature Stripping & Truncation Attacks", func() {
		It("rejects tokens stripped of their signature part", func() {
			claims := NewJwtClaimsSet()
			claims.Subject = "legit-user"
			claims.ExpiresAt = time.Now().Add(10 * time.Minute)

			tok, err := NewDefaultJwtEncoder(km).Encode(&JwtEncoderParameters{ClaimsSet: claims})
			Expect(err).NotTo(HaveOccurred())

			// 2-part token (signature omitted completely)
			parts := []byte(tok.TokenValue)
			dotIndex := -1
			for i, part := range slices.Backward(parts) {
				if part == '.' {
					dotIndex = i
					break
				}
			}
			Expect(dotIndex).To(BeNumerically(">", 0))
			strippedToken := string(parts[:dotIndex])

			_, decodeErr := decoder.Decode(strippedToken)
			Expect(decodeErr).To(HaveOccurred())
			Expect(decodeErr.Name()).To(Equal("InvalidJwtFormatError"))

			// 3-part token with trailing dot but blank signature
			blankSigToken := strippedToken + "."
			_, decodeErr = decoder.Decode(blankSigToken)
			Expect(decodeErr).To(HaveOccurred())
		})

		It("rejects tokens with a tampered or single-bit-flipped signature", func() {
			claims := NewJwtClaimsSet()
			claims.Subject = "alice"
			claims.ExpiresAt = time.Now().Add(10 * time.Minute)

			tok, err := NewDefaultJwtEncoder(km).Encode(&JwtEncoderParameters{ClaimsSet: claims})
			Expect(err).NotTo(HaveOccurred())

			// Flip the last bytes of the signature ensuring it always differs
			replacement := "AA"
			if tok.TokenValue[len(tok.TokenValue)-2:] == "AA" {
				replacement = "BB"
			}
			tampered := tok.TokenValue[:len(tok.TokenValue)-2] + replacement
			_, decodeErr := decoder.Decode(tampered)
			Expect(decodeErr).To(HaveOccurred())
			Expect(decodeErr.Name()).To(Equal("SignatureVerificationError"))
		})
	})

	Context("Key ID (kid) Tampering & Traversal Attacks", func() {
		It("rejects directory traversal and injection payloads in kid", func() {
			traversalKids := []string{
				"../../../../../../etc/passwd",
				"../../dev/null",
				"' OR 1=1 --",
				"<script>alert(1)</script>",
				"nonexistent-kid-404",
			}

			payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"tamperer"}`))

			for _, badKid := range traversalKids {
				header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"` + badKid + `"}`))
				fakeSig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature-bytes-padding-1234567890"))
				token := header + "." + payload + "." + fakeSig

				_, err := decoder.Decode(token)
				Expect(err).To(HaveOccurred(), "Must safely reject bad kid: "+badKid)
				Expect(err.Name()).To(Equal("UnknownKeyIdError"))
			}
		})
	})

	Context("Time-Bound Boundary Attacks (exp & nbf)", func() {
		It("rejects expired tokens just past clock skew boundary", func() {
			skewDecoder := NimbusJwtDecoder{}.New(km).WithClockSkew(2 * time.Second)

			claims := NewJwtClaimsSet()
			claims.Subject = "expiring-user"
			// Expired 5 seconds ago (past 2s skew)
			claims.ExpiresAt = time.Now().Add(-5 * time.Second)

			tok, err := NewDefaultJwtEncoder(km).Encode(&JwtEncoderParameters{ClaimsSet: claims})
			Expect(err).NotTo(HaveOccurred())

			_, decodeErr := skewDecoder.Decode(tok.TokenValue)
			Expect(decodeErr).To(HaveOccurred())
			Expect(decodeErr.Name()).To(Equal("JwtExpiredError"))
		})

		It("rejects not-yet-valid tokens ahead of clock skew boundary", func() {
			skewDecoder := NimbusJwtDecoder{}.New(km).WithClockSkew(2 * time.Second)

			claims := NewJwtClaimsSet()
			claims.Subject = "future-user"
			// Not valid for another 10 seconds (ahead of 2s skew)
			claims.NotBefore = time.Now().Add(10 * time.Second)
			claims.ExpiresAt = time.Now().Add(1 * time.Hour)

			tok, err := NewDefaultJwtEncoder(km).Encode(&JwtEncoderParameters{ClaimsSet: claims})
			Expect(err).NotTo(HaveOccurred())

			_, decodeErr := skewDecoder.Decode(tok.TokenValue)
			Expect(decodeErr).To(HaveOccurred())
			Expect(decodeErr.Name()).To(Equal("JwtNotYetValidError"))
		})
	})

	Context("JwxJwtDecoder Security Boundaries", func() {
		It("rejects tampered tokens with jwx key set validation", func() {
			pubKey, _, err := km.GetVerificationKey("security-test-key")
			Expect(err).NotTo(HaveOccurred())

			rsaPub, ok := pubKey.(*rsa.PublicKey)
			Expect(ok).To(BeTrue())

			jwkKey, jwkErr := jwk.Import(rsaPub)
			Expect(jwkErr).NotTo(HaveOccurred())
			Expect(jwkKey.Set(jwk.KeyIDKey, "security-test-key")).To(Succeed())
			Expect(jwkKey.Set(jwk.AlgorithmKey, jwa.RS256())).To(Succeed())

			keySet := jwk.NewSet()
			Expect(keySet.AddKey(jwkKey)).To(Succeed())

			jwxDec := JwxJwtDecoder{}.NewWithKeySet(keySet)

			// Sign valid token
			_, privKey, _, keyErr := km.GetSigningKey()
			Expect(keyErr).NotTo(HaveOccurred())

			encoder := JwxJwtEncoder{}.New(privKey, jwa.RS256(), "security-test-key")
			claims := NewJwtClaimsSet()
			claims.Subject = "alice"
			claims.ExpiresAt = time.Now().Add(5 * time.Minute)

			tok, encErr := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claims})
			Expect(encErr).NotTo(HaveOccurred())

			// Tamper token payload
			tamperedTok := tok.TokenValue[:len(tok.TokenValue)-5] + "XXXXX"
			_, decErr := jwxDec.Decode(tamperedTok)
			Expect(decErr).To(HaveOccurred())
			Expect(decErr.Name()).To(Equal("JwtParseError"))
		})
	})
})
