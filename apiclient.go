package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("api %s returned %d: %s", path, resp.StatusCode, body)
	}

	if dst != nil {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// post performs an authenticated POST and decodes JSON into dst.
func (c *apiClient) post(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, nil)
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

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted &&
		resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("api %s returned %d: %s", path, resp.StatusCode, body)
	}

	if dst != nil {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// NodeInfo holds the response from GET /api/v1/node.
type NodeInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Uptime   string `json:"uptime"`
}

// UpdateStatus holds the response from GET /api/v1/plugins/update/status.
type UpdateStatus struct {
	Running       bool   `json:"running"`
	LastRun       string `json:"last_run,omitempty"`
	LastResult    string `json:"last_result,omitempty"`
	PendingCount  int    `json:"pending_count"`
	SecurityCount int    `json:"security_count"`
}

// UpdateConfig holds the response from GET /api/v1/plugins/update/config.
type UpdateConfig struct {
	SecurityAvailable  *bool  `json:"security_available"`
	AutoSecurityUpdate bool   `json:"auto_security_updates"`
	Schedule           string `json:"schedule,omitempty"`
}

// NetworkInterface holds one entry from GET /api/v1/plugins/network/interfaces.
type NetworkInterface struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	State   string `json:"state"`
	Address string `json:"address,omitempty"`
	Gateway string `json:"gateway,omitempty"`
}

// NetworkStatus holds the response from GET /api/v1/plugins/network/status.
type NetworkStatus struct {
	Online     bool   `json:"online"`
	DNSWorking bool   `json:"dns_working"`
	PublicIP   string `json:"public_ip,omitempty"`
}

// DNSConfig holds the response from GET /api/v1/plugins/network/dns.
type DNSConfig struct {
	Servers []string `json:"servers"`
	Search  []string `json:"search,omitempty"`
}
