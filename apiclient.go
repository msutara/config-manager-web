package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// ---------- API client ----------

// apiClient makes authenticated requests to the CM JSON API.
type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newAPIClient(baseURL, token string) *apiClient {
	return &apiClient{
		baseURL: baseURL,
		token:   token,
		http: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// get performs an authenticated GET and decodes JSON into dst.
func (c *apiClient) get(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // best-effort error detail
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return fmt.Errorf("api %s returned %d redirect to %s: %s", path, resp.StatusCode, loc, respBody)
		}
		return fmt.Errorf("api %s returned %d: %s", path, resp.StatusCode, respBody)
	}

	if dst != nil {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

// post performs an authenticated POST with an optional body and decodes JSON into dst.
func (c *apiClient) post(ctx context.Context, path string, body io.Reader, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted &&
		resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // best-effort error detail
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return fmt.Errorf("api %s returned %d redirect to %s: %s", path, resp.StatusCode, loc, respBody)
		}
		return fmt.Errorf("api %s returned %d: %s", path, resp.StatusCode, respBody)
	}

	if dst != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

// put performs an authenticated PUT with a JSON body and decodes JSON into dst.
func (c *apiClient) put(ctx context.Context, path string, body io.Reader, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // best-effort error detail
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return fmt.Errorf("api %s returned %d redirect to %s: %s", path, resp.StatusCode, loc, respBody)
		}
		return fmt.Errorf("api %s returned %d: %s", path, resp.StatusCode, respBody)
	}

	if dst != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}

// ---------- Plugin settings ----------

// validPluginName matches plugin names: lowercase alphanumeric with hyphens,
// no leading/trailing hyphens. Blocks path traversal.
var validPluginName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// PluginSettings holds the response from GET /api/v1/plugins/{name}/settings.
type PluginSettings struct {
	Config map[string]any `json:"config"`
}

// PluginSettingsUpdateResult holds the response from PUT /api/v1/plugins/{name}/settings.
type PluginSettingsUpdateResult struct {
	Config  map[string]any `json:"config"`
	Warning string         `json:"warning,omitempty"`
}

// updatePluginSetting changes a single setting key for a plugin.
func (c *apiClient) updatePluginSetting(ctx context.Context, name, key string, value any) (*PluginSettingsUpdateResult, error) {
	if !validPluginName.MatchString(name) {
		return nil, fmt.Errorf("invalid plugin name: %q", name)
	}
	payload, err := json.Marshal(struct {
		Key   string `json:"key"`
		Value any    `json:"value"`
	}{Key: key, Value: value})
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	var r PluginSettingsUpdateResult
	if err := c.put(ctx, "/api/v1/plugins/"+name+"/settings", bytes.NewReader(payload), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ---------- Generic types (plugin registry) ----------

// PluginEndpoint describes a single endpoint exposed by a plugin.
type PluginEndpoint struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Description string `json:"description"`
}

// PluginInfo holds metadata returned by GET /api/v1/plugins.
type PluginInfo struct {
	Name        string           `json:"name"`
	Version     string           `json:"version"`
	Description string           `json:"description"`
	RoutePrefix string           `json:"route_prefix"`
	Endpoints   []PluginEndpoint `json:"endpoints"`
}

// ---------- Core types ----------

// NodeInfo holds the response from GET /api/v1/node.
type NodeInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Kernel        string `json:"kernel"`
	Arch          string `json:"arch"`
	UptimeSeconds int    `json:"uptime_seconds"`
}

// ---------- Update plugin types ----------

// PendingUpdate holds one entry from GET /api/v1/plugins/update/status.
type PendingUpdate struct {
	Package        string `json:"package"`
	CurrentVersion string `json:"current_version"`
	NewVersion     string `json:"new_version"`
	Security       bool   `json:"security"`
}

// RunStatus holds the response from GET /api/v1/plugins/update/logs.
type RunStatus struct {
	Type      string `json:"type"`
	Status    string `json:"status"`
	StartedAt string `json:"started_at,omitempty"`
	Duration  string `json:"duration,omitempty"`
	Packages  int    `json:"packages"`
	Log       string `json:"log,omitempty"`
}

// UpdateConfig holds the response from GET /api/v1/plugins/update/config.
type UpdateConfig struct {
	SecurityAvailable *bool  `json:"security_available"`
	AutoSecurity      *bool  `json:"auto_security"`
	SecuritySource    string `json:"security_source,omitempty"`
	Schedule          string `json:"schedule,omitempty"`
}

// ---------- Network plugin types ----------

// NetworkInterface holds one entry from GET /api/v1/plugins/network/interfaces.
type NetworkInterface struct {
	Name  string `json:"name"`
	MAC   string `json:"mac"`
	IP    string `json:"ip,omitempty"`
	State string `json:"state"`
}

// NetworkStatus holds the response from GET /api/v1/plugins/network/status.
type NetworkStatus struct {
	DefaultGateway    string `json:"default_gateway,omitempty"`
	DNSReachable      bool   `json:"dns_reachable"`
	InternetReachable bool   `json:"internet_reachable"`
}

// DNSConfig holds the response from GET /api/v1/plugins/network/dns.
type DNSConfig struct {
	Nameservers []string `json:"nameservers"`
	Search      []string `json:"search,omitempty"`
}
