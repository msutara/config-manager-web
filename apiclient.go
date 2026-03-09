package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// maxResponseBytes caps the amount of response body data the client will read
// before decoding JSON. This prevents unbounded memory allocation when the API
// returns unexpectedly large payloads — important on ARM devices with limited RAM.
const maxResponseBytes = 2 << 20 // 2 MB

// sanitizeTransportError strips internal URLs from HTTP client errors.
func sanitizeTransportError(err error) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("api request failed: %s", urlErr.Err)
	}
	return err
}

// decodeJSON reads up to maxResponseBytes+1 from r, returning a clear error
// when the response exceeds the limit rather than the ambiguous "unexpected
// EOF" produced by json.NewDecoder over io.LimitReader.
func decodeJSON(r io.Reader, dst any) error {
	buf, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(buf) > maxResponseBytes {
		return fmt.Errorf("response body exceeds %d byte limit", maxResponseBytes)
	}
	if err := json.Unmarshal(buf, dst); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
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

// String masks the auth token to prevent accidental exposure in logs or fmt output.
func (c *apiClient) String() string {
	return fmt.Sprintf("apiClient{baseURL:%q, token:[REDACTED]}", c.baseURL)
}

// GoString masks the auth token in %#v formatting.
func (c *apiClient) GoString() string {
	return c.String()
}

// apiErrorEnvelope matches the standard error JSON from the core API:
//
//	{"error":{"code":"...","message":"..."}}
type apiErrorEnvelope struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// APIError is returned when the core API responds with a non-2xx status code.
// Callers can type-assert to distinguish retryable server errors (5xx) from
// non-retryable client errors (4xx).
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string { return e.Message }

// Retryable returns true for 5xx and 429 (rate-limit) status codes.
// 4xx errors (except 429) indicate a permanent problem and should not be retried.
func (e *APIError) Retryable() bool {
	return e.StatusCode >= 500 || e.StatusCode == http.StatusTooManyRequests
}

// friendlyAPIError extracts a human-readable message from a raw JSON error
// body.  If the body is a well-formed error envelope with a message, only the
// message is returned.  Otherwise it falls back to the full body.
func friendlyAPIError(status int, body []byte) *APIError {
	var env apiErrorEnvelope
	if json.Unmarshal(body, &env) == nil && env.Error.Message != "" {
		return &APIError{StatusCode: status, Message: env.Error.Message}
	}
	return &APIError{StatusCode: status, Message: fmt.Sprintf("api returned %d: %s", status, body)}
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
		return sanitizeTransportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // best-effort error detail
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return &APIError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("api request returned %d redirect to %s: %s", resp.StatusCode, loc, respBody)}
		}
		return friendlyAPIError(resp.StatusCode, respBody)
	}

	if dst != nil {
		if err := decodeJSON(resp.Body, dst); err != nil {
			return err
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
		return sanitizeTransportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted &&
		resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // best-effort error detail
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return &APIError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("api request returned %d redirect to %s: %s", resp.StatusCode, loc, respBody)}
		}
		return friendlyAPIError(resp.StatusCode, respBody)
	}

	if dst != nil && resp.StatusCode != http.StatusNoContent {
		if err := decodeJSON(resp.Body, dst); err != nil {
			return err
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
		return sanitizeTransportError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // best-effort error detail
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return &APIError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("api request returned %d redirect to %s: %s", resp.StatusCode, loc, respBody)}
		}
		return friendlyAPIError(resp.StatusCode, respBody)
	}

	if dst != nil && resp.StatusCode != http.StatusNoContent {
		if err := decodeJSON(resp.Body, dst); err != nil {
			return err
		}
	}

	return nil
}

// doRequest executes an HTTP request with standard error handling and JSON decoding.
// Optional request modifiers (opts) allow callers to set additional headers.
func (c *apiClient) doRequest(ctx context.Context, method, path string, body io.Reader, dst any, opts ...func(*http.Request)) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for _, opt := range opts {
		opt(req)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return sanitizeTransportError(err)
	}
	defer resp.Body.Close()

	// Accept 200, 204 for all methods; additionally 202 for POST.
	ok := resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusNoContent ||
		(method == http.MethodPost && resp.StatusCode == http.StatusAccepted)
	if !ok {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // best-effort error detail
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return &APIError{StatusCode: resp.StatusCode, Message: fmt.Sprintf("api request returned %d redirect to %s: %s", resp.StatusCode, loc, respBody)}
		}
		return friendlyAPIError(resp.StatusCode, respBody)
	}

	if dst != nil && resp.StatusCode != http.StatusNoContent {
		if err := decodeJSON(resp.Body, dst); err != nil {
			return err
		}
	}
	return nil
}

// withConfirm sets the X-Confirm header on a request.
func withConfirm(req *http.Request) { req.Header.Set("X-Confirm", "true") }

// putConfirm performs a PUT with X-Confirm: true header.
func (c *apiClient) putConfirm(ctx context.Context, path string, body io.Reader, dst any) error {
	return c.doRequest(ctx, http.MethodPut, path, body, dst, withConfirm)
}

// deleteConfirm performs a DELETE with X-Confirm: true header.
func (c *apiClient) deleteConfirm(ctx context.Context, path string, dst any) error {
	return c.doRequest(ctx, http.MethodDelete, path, nil, dst, withConfirm)
}

// postConfirm performs a POST with X-Confirm: true header (no body).
func (c *apiClient) postConfirm(ctx context.Context, path string, dst any) error {
	return c.doRequest(ctx, http.MethodPost, path, nil, dst, withConfirm)
}

// ---------- Job history ----------

// listJobRuns fetches paginated job execution history for a job.
func (c *apiClient) listJobRuns(ctx context.Context, jobID string, limit, offset int) ([]JobRun, error) {
	if !validJobID.MatchString(jobID) {
		return nil, fmt.Errorf("invalid job id: %q", jobID)
	}
	path := fmt.Sprintf("/api/v1/jobs/%s/runs?limit=%d&offset=%d", jobID, limit, offset)
	var runs []JobRun
	if err := c.get(ctx, path, &runs); err != nil {
		return nil, err
	}
	return runs, nil
}

// ---------- Plugin settings ----------

// validPluginName matches plugin names according to the router's constraint:
// leading lowercase letter, followed by lowercase alphanumeric or hyphens.
var validPluginName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

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

// JobRun holds a job execution record returned by GET /api/v1/jobs/{id}/runs/latest
// and GET /api/v1/jobs/{id}/runs (paginated list).
type JobRun struct {
	JobID     string `json:"job_id"`
	Status    string `json:"status"` // Core API: "running", "completed", "failed"; web-layer synthetic: "error"
	StartedAt string `json:"started_at,omitempty"`
	EndedAt   string `json:"ended_at,omitempty"`
	Duration  string `json:"duration,omitempty"`
	Error     string `json:"error,omitempty"`
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

// NetworkWriteResult is the response from network write operations.
type NetworkWriteResult struct {
	Valid    bool           `json:"valid,omitempty"`
	Changes  []string       `json:"changes,omitempty"`
	Current  map[string]any `json:"current,omitempty"`
	Proposed map[string]any `json:"proposed,omitempty"`
	Message  string         `json:"message,omitempty"`
}
