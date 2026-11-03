package resourceserver

const (
	// defaultAuthorityPrefix is the default prefix applied to scope-based granted authorities.
	defaultAuthorityPrefix = "SCOPE_"
	// defaultPrincipalClaimName is the default claim name used to extract the principal's identifier.
	defaultPrincipalClaimName = "sub"
	// claimScope is the standard OAuth 2.0 scope claim name.
	claimScope = "scope"
	// claimScp is an alternative scope claim name used by some identity providers.
	claimScp = "scp"
)
