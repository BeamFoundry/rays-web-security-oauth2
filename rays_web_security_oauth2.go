// Package rays_web_security_oauth2 provides enterprise OAuth 2.0 and OpenID Connect 1.0 support
// for the Rays framework and rays-web-security, modeled after Spring Security OAuth2.
//
// # Modules
//
//   - [github.com/BeamFoundry/rays-web-security-oauth2/pkg/core]: Core domain models, tokens, and OAuth2 exceptions.
//   - [github.com/BeamFoundry/rays-web-security-oauth2/pkg/jwt]: JWT parsing, cryptographic signing (RSA/HMAC), validation, and JWK sets.
//   - [github.com/BeamFoundry/rays-web-security-oauth2/pkg/client]: OAuth2 Client management, repositories, token refresh, and client credentials.
//   - [github.com/BeamFoundry/rays-web-security-oauth2/pkg/login]: OAuth2 Login filter, authorization code exchange with PKCE, and UserInfo/OIDC services.
//   - [github.com/BeamFoundry/rays-web-security-oauth2/pkg/resourceserver]: Bearer token filter, token resolver, and JWT/Opaque authentication providers.
//   - [github.com/BeamFoundry/rays-web-security-oauth2/pkg/server]: Full OAuth 2.1 / OIDC 1.0 Authorization Server with authorization, token, jwks, and discovery endpoints.
//   - [github.com/BeamFoundry/rays-web-security-oauth2/pkg/config]: Fluent configurers for HttpSecurityBuilder.
package rays_web_security_oauth2 //nolint:revive // Ignoring package naming hint

import (
	_ "github.com/BeamFoundry/rays-web-security-oauth2/pkg/config"         // Autoconfig
	_ "github.com/BeamFoundry/rays-web-security-oauth2/pkg/login"          // Autoconfig
	_ "github.com/BeamFoundry/rays-web-security-oauth2/pkg/resourceserver" // Autoconfig
	_ "github.com/BeamFoundry/rays-web-security-oauth2/pkg/server"         // Autoconfig
)
