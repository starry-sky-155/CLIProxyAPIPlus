// Package copilot provides authentication and token management for GitHub Copilot API.
// It handles the OAuth2 device flow for secure authentication with the Copilot API.
package copilot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	log "github.com/sirupsen/logrus"
)

const (
	// copilotAPITokenURL is the endpoint for getting Copilot API tokens from GitHub token.
	copilotAPITokenURL = "https://api.github.com/copilot_internal/v2/token"
	// copilotAPIEndpoint is the base URL for making API requests.
	copilotAPIEndpoint = "https://api.githubcopilot.com"

	copilotUserAgent    = "opencode/0.1.91"
	copilotOpenAIIntent = "conversation-edits"
)

// CopilotAPIToken represents the Copilot API token response.
type CopilotAPIToken struct {
	// Token is the JWT token for authenticating with the Copilot API.
	Token string `json:"token"`
	// ExpiresAt is the Unix timestamp when the token expires.
	ExpiresAt int64 `json:"expires_at"`
	// Endpoints contains the available API endpoints.
	Endpoints struct {
		API           string `json:"api"`
		Proxy         string `json:"proxy"`
		OriginTracker string `json:"origin-tracker"`
		Telemetry     string `json:"telemetry"`
	} `json:"endpoints,omitempty"`
	// ErrorDetails contains error information if the request failed.
	ErrorDetails *struct {
		URL              string `json:"url"`
		Message          string `json:"message"`
		DocumentationURL string `json:"documentation_url"`
	} `json:"error_details,omitempty"`
}

// CopilotAuth handles GitHub Copilot authentication flow.
// It provides methods for device flow authentication and token management.
type CopilotAuth struct {
	httpClient   *http.Client
	deviceClient *DeviceFlowClient
	cfg          *config.Config
}

// NewCopilotAuth creates a new CopilotAuth service instance.
// It initializes an HTTP client with proxy settings from the provided configuration.
func NewCopilotAuth(cfg *config.Config) *CopilotAuth {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &CopilotAuth{
		httpClient:   util.SetProxy(&cfg.SDKConfig, &http.Client{Timeout: 30 * time.Second}),
		deviceClient: NewDeviceFlowClient(cfg),
		cfg:          cfg,
	}
}

// StartDeviceFlow initiates the device flow authentication.
// Returns the device code response containing the user code and verification URI.
func (c *CopilotAuth) StartDeviceFlow(ctx context.Context) (*DeviceCodeResponse, error) {
	return c.deviceClient.RequestDeviceCode(ctx)
}

// WaitForAuthorization polls for user authorization and returns the auth bundle.
func (c *CopilotAuth) WaitForAuthorization(ctx context.Context, deviceCode *DeviceCodeResponse) (*CopilotAuthBundle, error) {
	tokenData, err := c.deviceClient.PollForToken(ctx, deviceCode)
	if err != nil {
		return nil, err
	}

	// Fetch the GitHub username
	userInfo, err := c.deviceClient.FetchUserInfo(ctx, tokenData.AccessToken)
	if err != nil {
		log.Warnf("copilot: failed to fetch user info: %v", err)
	}

	username := userInfo.Login
	if username == "" {
		username = "github-user"
	}

	return &CopilotAuthBundle{
		TokenData: tokenData,
		Username:  username,
		Email:     userInfo.Email,
		Name:      userInfo.Name,
	}, nil
}

// GetCopilotAPIToken exchanges a GitHub access token for a Copilot API token.
// This token is used to make authenticated requests to the Copilot API.
func (c *CopilotAuth) GetCopilotAPIToken(ctx context.Context, githubAccessToken string) (*CopilotAPIToken, error) {
	if githubAccessToken == "" {
		return nil, NewAuthenticationError(ErrTokenExchangeFailed, fmt.Errorf("github access token is empty"))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, copilotAPITokenURL, nil)
	if err != nil {
		return nil, NewAuthenticationError(ErrTokenExchangeFailed, err)
	}

	req.Header.Set("Authorization", "token "+githubAccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", copilotUserAgent)
	util.ApplyCustomHeaders(req, c.githubCopilotHeaders())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, NewAuthenticationError(ErrTokenExchangeFailed, err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("copilot api token: close body error: %v", errClose)
		}
	}()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, NewAuthenticationError(ErrTokenExchangeFailed, err)
	}

	if !isHTTPSuccess(resp.StatusCode) {
		return nil, NewAuthenticationError(ErrTokenExchangeFailed,
			fmt.Errorf("status %d: %s", resp.StatusCode, string(bodyBytes)))
	}

	var apiToken CopilotAPIToken
	if err = json.Unmarshal(bodyBytes, &apiToken); err != nil {
		return nil, NewAuthenticationError(ErrTokenExchangeFailed, err)
	}

	if apiToken.Token == "" {
		return nil, NewAuthenticationError(ErrTokenExchangeFailed, fmt.Errorf("empty copilot api token"))
	}

	return &apiToken, nil
}

// ValidateToken checks if a GitHub access token is valid by attempting to fetch user info.
func (c *CopilotAuth) ValidateToken(ctx context.Context, accessToken string) (bool, string, error) {
	if accessToken == "" {
		return false, "", nil
	}

	userInfo, err := c.deviceClient.FetchUserInfo(ctx, accessToken)
	if err != nil {
		return false, "", err
	}

	return true, userInfo.Login, nil
}

// CreateTokenStorage creates a new CopilotTokenStorage from auth bundle.
func (c *CopilotAuth) CreateTokenStorage(bundle *CopilotAuthBundle) *CopilotTokenStorage {
	return &CopilotTokenStorage{
		AccessToken: bundle.TokenData.AccessToken,
		TokenType:   bundle.TokenData.TokenType,
		Scope:       bundle.TokenData.Scope,
		Username:    bundle.Username,
		Email:       bundle.Email,
		Name:        bundle.Name,
		Type:        "github-copilot",
	}
}

// LoadAndValidateToken loads a token from storage and validates it.
// Returns the storage if valid, or an error if the token is invalid or expired.
func (c *CopilotAuth) LoadAndValidateToken(ctx context.Context, storage *CopilotTokenStorage) (bool, error) {
	if storage == nil || storage.AccessToken == "" {
		return false, fmt.Errorf("no token available")
	}

	valid, _, err := c.ValidateToken(ctx, storage.AccessToken)
	if err != nil {
		return false, err
	}

	return valid, nil
}

// GetAPIEndpoint returns the Copilot API endpoint URL.
func (c *CopilotAuth) GetAPIEndpoint() string {
	return copilotAPIEndpoint
}

// MakeAuthenticatedRequest creates an authenticated HTTP request to the Copilot API.
func (c *CopilotAuth) MakeAuthenticatedRequest(ctx context.Context, method, url string, body io.Reader, bearerToken string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", copilotUserAgent)
	req.Header.Set("Openai-Intent", copilotOpenAIIntent)
	util.ApplyCustomHeaders(req, c.githubCopilotHeaders())

	return req, nil
}

func (c *CopilotAuth) githubCopilotHeaders() map[string]string {
	if c == nil || c.cfg == nil {
		return nil
	}
	return c.cfg.GitHubCopilot.Headers
}

// CopilotModelEntry represents a single model entry returned by the Copilot /models API.
type CopilotModelEntry struct {
	ID           string         `json:"id"`
	Object       string         `json:"object"`
	Created      int64          `json:"created"`
	OwnedBy      string         `json:"owned_by"`
	Name         string         `json:"name,omitempty"`
	Version      string         `json:"version,omitempty"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
}

// CopilotModelsResponse represents the response from the Copilot /models endpoint.
type CopilotModelsResponse struct {
	Data   []CopilotModelEntry `json:"data"`
	Object string              `json:"object"`
}

// maxModelsResponseSize is the maximum allowed response size from the /models endpoint (2 MB).
const maxModelsResponseSize = 2 * 1024 * 1024

// ListModels fetches the list of available models from the Copilot API.
func (c *CopilotAuth) ListModels(ctx context.Context, bearerToken string) ([]CopilotModelEntry, error) {
	if bearerToken == "" {
		return nil, fmt.Errorf("copilot: bearer token is required for listing models")
	}

	modelsURL := copilotAPIEndpoint + "/models"

	req, err := c.MakeAuthenticatedRequest(ctx, http.MethodGet, modelsURL, nil, bearerToken)
	if err != nil {
		return nil, fmt.Errorf("copilot: failed to create models request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("copilot: models request failed: %w", err)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("copilot list models: close body error: %v", errClose)
		}
	}()

	// Limit response body to prevent memory exhaustion.
	limitedReader := io.LimitReader(resp.Body, maxModelsResponseSize)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("copilot: failed to read models response: %w", err)
	}

	if !isHTTPSuccess(resp.StatusCode) {
		return nil, fmt.Errorf("copilot: list models failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var modelsResp CopilotModelsResponse
	if err = json.Unmarshal(bodyBytes, &modelsResp); err != nil {
		return nil, fmt.Errorf("copilot: failed to parse models response: %w", err)
	}

	return modelsResp.Data, nil
}

// ListModelsWithGitHubToken fetches available models using the GitHub access token directly.
func (c *CopilotAuth) ListModelsWithGitHubToken(ctx context.Context, githubAccessToken string) ([]CopilotModelEntry, error) {
	return c.ListModels(ctx, githubAccessToken)
}

// buildChatCompletionURL builds the URL for chat completions API.
func buildChatCompletionURL() string {
	return copilotAPIEndpoint + "/chat/completions"
}

// isHTTPSuccess checks if the status code indicates success (2xx).
func isHTTPSuccess(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}
