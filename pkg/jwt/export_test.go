package jwt

import (
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
