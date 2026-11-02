package jwt_test

import (
	"testing"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt"
)

func FuzzParseUnverified(f *testing.F) {
	// Seed corpus with various tokens
	f.Add("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
	f.Add("")
	f.Add("invalid")
	f.Add("..")
	f.Add("a.b.c")
	f.Add("a.b.c.d")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.")
	f.Add("\x00\x01\x02.\x03\x04\x05.\x06\x07\x08")
	f.Add("eyJhbGciOiJSUzI1NiJ9.eyJyZWN1cnNpb24iOltbW1tbW1tdXVdfX0.sig")

	f.Fuzz(func(_ *testing.T, token string) {
		// Must never panic on arbitrary string inputs
		_, _, err := ParseUnverified(token)
		if err != nil {
			err.LogError()
		}
	})
}

func FuzzNimbusJwtDecoder(f *testing.F) {
	km, err := RSAKeyManager{}.New(2048, "fuzz-key")
	if err != nil {
		f.Fatalf("failed to create rsa key manager: %v", err)
	}

	encoder := DefaultJwtEncoder{}.New(km)
	claims := NewJwtClaimsSet()
	claims.Subject = "fuzz-user"
	claims.Issuer = "https://auth.example.com"
	claims.ExpiresAt = time.Now().Add(10 * time.Minute)
	validToken, encErr := encoder.Encode(&JwtEncoderParameters{ClaimsSet: claims})
	if encErr != nil {
		f.Fatalf("failed to encode valid token: %v", encErr)
	}

	decoder := NimbusJwtDecoder{}.New(km)

	f.Add(validToken.TokenValue)
	f.Add("")
	f.Add("..")
	f.Add("invalid.jwt.token")
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.")
	f.Add(validToken.TokenValue + ".extra")
	f.Add("\x00\xff\xfe")

	f.Fuzz(func(_ *testing.T, token string) {
		// Must never panic on arbitrary string inputs
		_, err := decoder.Decode(token)
		if err != nil {
			err.LogError()
		}
	})
}
