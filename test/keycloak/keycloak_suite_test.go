package keycloak_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/BeamFoundry/rays/pkg/lang"

	keycloak "github.com/stillya/testcontainers-keycloak"
)

func TestKeycloak(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Keycloak Integration Suite")
}

var (
	keycloakContainer *keycloak.KeycloakContainer
	keycloakBaseURL   string
	realmName         = "rays-realm"
)

func startKeycloak() {
	ctx := context.Background()
	realmAbs, err := filepath.Abs("testdata/realm-rays.json")
	Expect(err).NotTo(HaveOccurred())

	keycloakContainer, err = keycloak.Run(
		ctx,
		"keycloak/keycloak:26.0",
		keycloak.WithRealmImportFile(realmAbs),
		keycloak.WithAdminUsername("admin"),
		keycloak.WithAdminPassword("admin"),
	)
	Expect(err).NotTo(HaveOccurred())

	keycloakBaseURL, err = keycloakContainer.GetAuthServerURL(ctx)
	Expect(err).NotTo(HaveOccurred())
	Expect(keycloakBaseURL).NotTo(BeEmpty())
}

func stopKeycloak() {
	if keycloakContainer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := keycloakContainer.Terminate(ctx); err != nil {
			NewErrorFrom(err).LogError()
		}
	}
}

type KeycloakTokens struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

// Helper to obtain full token set from Keycloak via Resource Owner Password Credentials
func obtainUserTokens(username, password string) (*KeycloakTokens, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakBaseURL, realmName)
	data := url.Values{
		"grant_type":    {"password"},
		"client_id":     {"rays-web-client"},
		"client_secret": {"web-client-secret"},
		"username":      {username},
		"password":      {password},
		"scope":         {"openid profile email"},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post form: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			NewErrorFrom(closeErr).LogError()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		b, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("token request failed (status %d): read body: %w", resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("token request failed (status %d): %s", resp.StatusCode, string(b))
	}

	var res KeycloakTokens
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	return &res, nil
}

// Helper to obtain a user access token from Keycloak
func obtainUserToken(username, password string) (string, error) {
	tokens, err := obtainUserTokens(username, password)
	if err != nil {
		return "", err
	}
	return tokens.AccessToken, nil
}
