package jwt

import (
	"crypto/rsa"
	"io"

	. "github.com/BeamFoundry/rays/pkg/lang"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/sync/singleflight"
)

// ParseJwtTimestampForTest exposes parseJwtTimestamp for unit tests.
var ParseJwtTimestampForTest = parseJwtTimestamp

// SetRefreshGroupForTest sets the singleflight.Group for testing.
func (this *JwxJwtDecoder) SetRefreshGroupForTest(rg *singleflight.Group) {
	this.refreshGroup = rg
}

// SetCachedSetForTest sets the cachedSet for testing.
func (this *JwxJwtDecoder) SetCachedSetForTest(cs jwk.CachedSet) {
	this.cachedSet = cs
}

// SetParseUnverifiedForTest sets parseUnverified for unit tests.
func SetParseUnverifiedForTest(fn func(string) (map[string]any, map[string]any, Error)) func() {
	orig := parseUnverified
	parseUnverified = fn
	return func() { parseUnverified = orig }
}

// SetRsaGenerateKeyForTest sets rsaGenerateKey for unit tests.
func SetRsaGenerateKeyForTest(fn func(io.Reader, int) (*rsa.PrivateKey, error)) func() {
	orig := rsaGenerateKey
	rsaGenerateKey = fn
	return func() { rsaGenerateKey = orig }
}
