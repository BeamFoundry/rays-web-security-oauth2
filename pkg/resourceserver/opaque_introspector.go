package resourceserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	. "github.com/BeamFoundry/rays-web-security-oauth2/pkg/core"
	. "github.com/BeamFoundry/rays-web-security/pkg/core"
	. "github.com/BeamFoundry/rays/pkg/lang"
)

// OpaqueTokenIntrospector validates an OAuth 2.0 token against an RFC 7662 introspection endpoint
type OpaqueTokenIntrospector interface {
	// Introspect validates the opaque token and returns the resulting OAuth2AuthenticatedPrincipal if active.
	Introspect(token string) (OAuth2AuthenticatedPrincipal, Error)
}

// NimbusOpaqueTokenIntrospector queries an OAuth 2.0 token introspection endpoint via HTTP POST
type NimbusOpaqueTokenIntrospector struct {
	httpClient         *http.Client
	introspectionURI   string
	clientID           string
	clientSecret       string
	authorityPrefix    string
	principalClaimName string
	authoritiesClaims  []string
	clockSkew          time.Duration
	timeout            time.Duration
}

// DefaultOpaqueTokenIntrospector is an alias to NimbusOpaqueTokenIntrospector
type DefaultOpaqueTokenIntrospector = NimbusOpaqueTokenIntrospector

var _ OpaqueTokenIntrospector = &NimbusOpaqueTokenIntrospector{}

// New creates a new NimbusOpaqueTokenIntrospector for the given RFC 7662 introspection endpoint URI and client credentials.
func (this NimbusOpaqueTokenIntrospector) New(
	introspectionURI string,
	clientID string,
	clientSecret string,
) *NimbusOpaqueTokenIntrospector {
	this.introspectionURI = introspectionURI
	this.clientID = clientID
	this.clientSecret = clientSecret
	this.httpClient = http.DefaultClient
	this.authorityPrefix = defaultAuthorityPrefix
	this.authoritiesClaims = []string{claimScope, claimScp, "authorities", "roles"}
	this.principalClaimName = defaultPrincipalClaimName
	this.clockSkew = 60 * time.Second
	this.timeout = 10 * time.Second
	return &this
}

// NewNimbusOpaqueTokenIntrospector creates a new NimbusOpaqueTokenIntrospector.
func NewNimbusOpaqueTokenIntrospector(
	introspectionURI string,
	clientID string,
	clientSecret string,
) *NimbusOpaqueTokenIntrospector {
	return NimbusOpaqueTokenIntrospector{}.New(introspectionURI, clientID, clientSecret)
}

// NewDefaultOpaqueTokenIntrospector creates a new NimbusOpaqueTokenIntrospector.
func NewDefaultOpaqueTokenIntrospector(
	introspectionURI string,
	clientID string,
	clientSecret string,
) *NimbusOpaqueTokenIntrospector {
	return NimbusOpaqueTokenIntrospector{}.New(introspectionURI, clientID, clientSecret)
}

// WithHTTPClient configures a custom HTTP client for introspection requests.
func (this *NimbusOpaqueTokenIntrospector) WithHTTPClient(client *http.Client) *NimbusOpaqueTokenIntrospector {
	if client != nil {
		this.httpClient = client
	}
	return this
}

// WithAuthorityPrefix sets the prefix prepended to authorities extracted from the introspection response.
// Values from "scope" and "scp" claims always receive the configured prefix (when non-empty), whereas role-style claim values from other authority claims already beginning with "ROLE_" or "SCOPE_" pass through unchanged.
func (this *NimbusOpaqueTokenIntrospector) WithAuthorityPrefix(prefix string) *NimbusOpaqueTokenIntrospector {
	this.authorityPrefix = prefix
	return this
}

// WithAuthoritiesClaims sets the claim names inspected to extract granted authorities from the introspection response.
func (this *NimbusOpaqueTokenIntrospector) WithAuthoritiesClaims(claims ...string) *NimbusOpaqueTokenIntrospector {
	this.authoritiesClaims = claims
	return this
}

// WithPrincipalClaimName sets the claim name used to determine the principal name from the introspection response.
func (this *NimbusOpaqueTokenIntrospector) WithPrincipalClaimName(name string) *NimbusOpaqueTokenIntrospector {
	this.principalClaimName = name
	return this
}

// WithClockSkew sets the acceptable clock skew duration when validating "exp" and "nbf" timestamps.
func (this *NimbusOpaqueTokenIntrospector) WithClockSkew(skew time.Duration) *NimbusOpaqueTokenIntrospector {
	this.clockSkew = skew
	return this
}

// WithTimeout sets the HTTP request timeout for token introspection calls.
func (this *NimbusOpaqueTokenIntrospector) WithTimeout(timeout time.Duration) *NimbusOpaqueTokenIntrospector {
	this.timeout = timeout
	return this
}

// Introspect performs an RFC 7662 token introspection request, validates token activity and temporal claims, and constructs an OAuth2AuthenticatedPrincipal.
func (this *NimbusOpaqueTokenIntrospector) Introspect(token string) (OAuth2AuthenticatedPrincipal, Error) {
	if this.introspectionURI == "" {
		return nil, NewError("InvalidConfigurationError", "introspectionURI must not be empty")
	}
	if strings.TrimSpace(token) == "" {
		return nil, OAuth2AuthenticationException{}.New(
			OAuth2Error{ErrorCode: OAuth2ErrorInvalidToken, ErrorDescription: "token cannot be empty"},
			nil,
		)
	}

	if valErr := validateIntrospectionURI(this.introspectionURI); valErr != nil {
		return nil, valErr
	}
	configuredURL, parseErr := url.Parse(this.introspectionURI)
	if parseErr != nil {
		return nil, NewErrorFrom(parseErr)
	}

	timeout := this.timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", "access_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, this.introspectionURI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, NewErrorFrom(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if this.clientID != "" || this.clientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(this.clientID), url.QueryEscape(this.clientSecret))
	}

	client := this.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	secureClient := *client
	originalCheckRedirect := client.CheckRedirect
	secureClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if redirectErr := validateIntrospectionURI(req.URL.String()); redirectErr != nil {
			return fmt.Errorf("insecure redirect in token introspection: %w", redirectErr)
		}
		if !isSameOrigin(req.URL, configuredURL) {
			return errors.New("insecure redirect in token introspection: redirect scheme, host, or port differs from configured introspection URI")
		}
		if originalCheckRedirect != nil {
			return originalCheckRedirect(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}

	resp, doErr := secureClient.Do(req)
	if doErr != nil {
		return nil, NewErrorFrom(doErr)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			NewErrorFrom(closeErr).LogError()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, OAuth2AuthenticationException{}.New(
			OAuth2Error{
				ErrorCode:        OAuth2ErrorInvalidToken,
				ErrorDescription: fmt.Sprintf("introspection endpoint returned status code %d", resp.StatusCode),
			},
			nil,
		)
	}

	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if readErr != nil {
		return nil, NewErrorFrom(readErr)
	}

	var claims map[string]any
	if unmarshalErr := json.Unmarshal(bodyBytes, &claims); unmarshalErr != nil {
		return nil, OAuth2AuthenticationException{}.New(
			OAuth2Error{
				ErrorCode:        OAuth2ErrorInvalidToken,
				ErrorDescription: "failed to parse introspection response: " + unmarshalErr.Error(),
			},
			nil,
		)
	}

	active, ok := claims["active"].(bool)
	if !ok || !active {
		return nil, OAuth2AuthenticationException{}.New(
			OAuth2Error{
				ErrorCode:        OAuth2ErrorInvalidToken,
				ErrorDescription: "provided token is not active",
			},
			nil,
		)
	}

	now := time.Now()
	if expVal, exists := claims["exp"]; exists {
		expSec, ok := parseIntegerTimestamp(expVal)
		if !ok {
			return nil, OAuth2AuthenticationException{}.New(
				OAuth2Error{
					ErrorCode:        OAuth2ErrorInvalidToken,
					ErrorDescription: "invalid exp claim",
				},
				nil,
			)
		}
		expTime := time.Unix(expSec, 0)
		if now.Add(-this.clockSkew).After(expTime) {
			return nil, OAuth2AuthenticationException{}.New(
				OAuth2Error{
					ErrorCode:        OAuth2ErrorInvalidToken,
					ErrorDescription: "token has expired",
				},
				nil,
			)
		}
	}

	if nbfVal, exists := claims["nbf"]; exists {
		nbfSec, ok := parseIntegerTimestamp(nbfVal)
		if !ok {
			return nil, OAuth2AuthenticationException{}.New(
				OAuth2Error{
					ErrorCode:        OAuth2ErrorInvalidToken,
					ErrorDescription: "invalid nbf claim",
				},
				nil,
			)
		}
		if nbfSec > 0 {
			nbfTime := time.Unix(nbfSec, 0)
			if now.Add(this.clockSkew).Before(nbfTime) {
				return nil, OAuth2AuthenticationException{}.New(
					OAuth2Error{
						ErrorCode:        OAuth2ErrorInvalidToken,
						ErrorDescription: "token is not yet valid",
					},
					nil,
				)
			}
		}
	}

	authorities := make([]GrantedAuthority, 0)
	addAuth := func(sourceClaim, s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if sourceClaim == claimScope || sourceClaim == claimScp {
			if this.authorityPrefix == "" {
				authorities = append(authorities, Authority(s))
			} else {
				authorities = append(authorities, Authority(this.authorityPrefix+s))
			}
			return
		}
		if strings.HasPrefix(s, "ROLE_") || strings.HasPrefix(s, "SCOPE_") || this.authorityPrefix == "" {
			authorities = append(authorities, Authority(s))
		} else {
			authorities = append(authorities, Authority(this.authorityPrefix+s))
		}
	}

	for _, claimKey := range this.authoritiesClaims {
		if val, exists := claims[claimKey]; exists {
			switch v := val.(type) {
			case string:
				for part := range strings.FieldsSeq(v) {
					addAuth(claimKey, part)
				}
			case []any:
				for _, item := range v {
					if s, strOk := item.(string); strOk {
						for part := range strings.FieldsSeq(s) {
							addAuth(claimKey, part)
						}
					}
				}
			case []string:
				for _, s := range v {
					for part := range strings.FieldsSeq(s) {
						addAuth(claimKey, part)
					}
				}
			default:
			}
		}
	}

	principalName := ""
	if this.principalClaimName != "" {
		if nameVal, strOk := claims[this.principalClaimName].(string); strOk && nameVal != "" {
			principalName = nameVal
		}
	}
	if principalName == "" {
		if sub, strOk := claims[defaultPrincipalClaimName].(string); strOk && sub != "" {
			principalName = sub
		} else if username, strOk := claims["username"].(string); strOk && username != "" {
			principalName = username
		} else if clientID, strOk := claims["client_id"].(string); strOk && clientID != "" {
			principalName = clientID
		}
	}

	return NewDefaultOAuth2AuthenticatedPrincipal(principalName, claims, authorities), nil
}

// validateIntrospectionURI ensures the introspection URI uses HTTPS, or HTTP only for loopback addresses.
func validateIntrospectionURI(rawURI string) Error {
	parsed, err := url.Parse(rawURI)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return NewError("IllegalArgumentException", "invalid introspection URI")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "https" {
		return nil
	}
	if scheme == "http" {
		if isLoopbackHost(parsed.Hostname()) {
			return nil
		}
		return NewError("IllegalArgumentException", "introspection URI must use HTTPS unless host is loopback")
	}
	return NewError("IllegalArgumentException", "introspection URI must use HTTPS or HTTP for loopback")
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isSameOrigin reports whether target and configured URLs share the same scheme, hostname, and effective port.
func isSameOrigin(target, configured *url.URL) bool {
	if target == nil || configured == nil {
		return false
	}
	if !strings.EqualFold(target.Scheme, configured.Scheme) {
		return false
	}
	if !strings.EqualFold(target.Hostname(), configured.Hostname()) {
		return false
	}
	return effectivePort(target) == effectivePort(configured)
}

// effectivePort returns the explicit port of u or the default port for its scheme (80 for http, 443 for https).
func effectivePort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return ""
}

// parseIntegerTimestamp converts a numeric or string claim value into a 64-bit integer Unix timestamp.
func parseIntegerTimestamp(val any) (int64, bool) {
	switch v := val.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v || v < math.MinInt64 || v >= math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	case json.Number:
		if p, parseErr := v.Int64(); parseErr == nil {
			return p, true
		}
	case string:
		if p, parseErr := strconv.ParseInt(v, 10, 64); parseErr == nil {
			return p, true
		}
	default:
	}
	return 0, false
}
