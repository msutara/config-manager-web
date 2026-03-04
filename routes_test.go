package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// boolPtr is a test helper for creating *bool literals.
func boolPtr(b bool) *bool { return &b }

// mockAPI creates a test server that simulates the CM JSON API.
func mockAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{
				Name: "update", Version: "0.1.0",
				Description: "System updates management",
				RoutePrefix: "/api/v1/plugins/update",
				Endpoints: []PluginEndpoint{
					{Method: "GET", Path: "/status", Description: "Pending updates and system info"},
					{Method: "GET", Path: "/config", Description: "Update plugin configuration"},
					{Method: "POST", Path: "/run", Description: "Trigger update run"},
				},
			},
			{
				Name: "network", Version: "0.1.0",
				Description: "Network configuration",
				RoutePrefix: "/api/v1/plugins/network",
				Endpoints: []PluginEndpoint{
					{Method: "GET", Path: "/interfaces", Description: "Network interface details"},
					{Method: "GET", Path: "/status", Description: "Connectivity status"},
				},
			},
			{
				Name: "firewall", Version: "0.1.0",
				Description: "Firewall management",
				RoutePrefix: "/api/v1/plugins/firewall",
				Endpoints: []PluginEndpoint{
					{Method: "GET", Path: "/rules", Description: "Active firewall rules"},
				},
			},
		})
	})

	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{
			Hostname:      "test-node",
			OS:            "Debian 12",
			Kernel:        "6.1.0",
			Arch:          "arm",
			UptimeSeconds: 191400,
		})
	})

	mux.HandleFunc("/api/v1/plugins/update/status", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PendingUpdate{
			{Package: "openssl", CurrentVersion: "3.0.1", NewVersion: "3.0.2", Security: true},
			{Package: "curl", CurrentVersion: "7.88.0", NewVersion: "7.88.1", Security: true},
			{Package: "vim", CurrentVersion: "9.0.1", NewVersion: "9.0.2", Security: false},
			{Package: "git", CurrentVersion: "2.39.0", NewVersion: "2.39.1", Security: false},
			{Package: "wget", CurrentVersion: "1.21.3", NewVersion: "1.21.4", Security: false},
		})
	})

	mux.HandleFunc("/api/v1/plugins/update/logs", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(RunStatus{
			Type:      "full",
			Status:    "completed",
			StartedAt: "2026-02-27T10:00:00Z",
			Packages:  3,
		})
	})

	mux.HandleFunc("/api/v1/plugins/update/config", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(UpdateConfig{
			SecurityAvailable: boolPtr(true),
			AutoSecurity:      boolPtr(true),
			SecuritySource:    "detected",
			Schedule:          "0 3 * * *",
		})
	})

	mux.HandleFunc("/api/v1/plugins/update/run", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "started"})
	})

	mux.HandleFunc("/api/v1/plugins/network/interfaces", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]NetworkInterface{
			{Name: "eth0", MAC: "aa:bb:cc:dd:ee:ff", State: "up", IP: "192.168.1.10/24"},
			{Name: "wlan0", MAC: "11:22:33:44:55:66", State: "down"},
		})
	})

	mux.HandleFunc("/api/v1/plugins/network/status", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NetworkStatus{
			InternetReachable: true,
			DNSReachable:      true,
			DefaultGateway:    "192.168.1.1",
		})
	})

	mux.HandleFunc("/api/v1/plugins/network/dns", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(DNSConfig{
			Nameservers: []string{"1.1.1.1", "8.8.8.8"},
			Search:      []string{"local"},
		})
	})

	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Key   string `json:"key"`
			Value any    `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config: map[string]any{body.Key: body.Value},
		})
	})

	return httptest.NewServer(mux)
}

// ---------- Helper function tests ----------

func TestCleanPluginPath(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		path   string
		want   string
	}{
		{"normal", "/api/v1/plugins/update", "/status", "/api/v1/plugins/update/status"},
		{"no leading slash", "/api/v1/plugins/update", "status", "/api/v1/plugins/update/status"},
		{"trailing slash prefix", "/api/v1/plugins/update/", "/status", "/api/v1/plugins/update/status"},
		{"traversal literal", "/api/v1/plugins/update", "/../../../etc/passwd", ""},
		{"traversal encoded", "/api/v1/plugins/update", "/%2e%2e/%2e%2e/secret", ""},
		{"double encoded", "/api/v1/plugins/update", "/%252e%252e/secret", ""},
		{"invalid escape", "/api/v1/plugins/update", "/%zz", ""},
		{"empty prefix", "", "/status", ""},
		{"root path", "/api/v1/plugins/update", "/", "/api/v1/plugins/update"},
		{"dot-in-segment", "/api/v1/plugins/update", "/..status", "/api/v1/plugins/update/..status"},
		{"null byte", "/api/v1/plugins/update", "/x%00y", ""},
		{"newline", "/api/v1/plugins/update", "/x%0ay", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanPluginPath(tt.prefix, tt.path)
			if got != tt.want {
				t.Errorf("cleanPluginPath(%q, %q) = %q, want %q", tt.prefix, tt.path, got, tt.want)
			}
		})
	}
}

func TestValidateRoutePrefix(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		wantErr bool
	}{
		{"valid prefix", "/api/v1/plugins/update", false},
		{"empty", "", true},
		{"no leading slash", "api/v1", true},
		{"traversal literal", "/api/../secret", true},
		{"traversal encoded", "/api/%2e%2e/secret", true},
		{"double encoded traversal", "/api/%252e%252e/secret", true},
		{"control character", "/api/\x00foo", true},
		{"clean prefix", "/api/v1/plugins/network", false},
		{"dot segment single", "/api/./v1", true},
		{"dot segment trailing", "/api/v1/.", true},
		{"dot segment double slash", "/api//v1", true},
		{"trailing slash valid", "/api/v1/plugins/update/", false},
		{"bare root slash rejected", "/", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRoutePrefix(tt.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRoutePrefix(%q) error = %v, wantErr %v", tt.prefix, err, tt.wantErr)
			}
		})
	}
}

func TestTitleCase(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"update", "Update"},
		{"network", "Network"},
		{"my-plugin", "My Plugin"},
		{"a-b-c", "A B C"},
		{"", ""},
		{"x", "X"},
		{"a--b", "A B"},
		{"trailing-", "Trailing"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := titleCase(tt.in)
			if got != tt.want {
				t.Errorf("titleCase(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ---------- API client tests ----------

func TestAPIClient_GetSuccess(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	c := newAPIClient(api.URL, "")
	var node NodeInfo
	if err := c.get(context.Background(), "/api/v1/node", &node); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if node.Hostname != "test-node" {
		t.Fatalf("hostname = %q, want %q", node.Hostname, "test-node")
	}
}

func TestAPIClient_GetNotFound(t *testing.T) {
	api := httptest.NewServer(http.NotFoundHandler())
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.get(context.Background(), "/nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("error should mention 404: %v", err)
	}
}

func TestAPIClient_PostSuccess(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.post(context.Background(), "/api/v1/plugins/update/run", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPIClient_BearerTokenSent(t *testing.T) {
	var gotAuth string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "test-token")
	if err := c.get(context.Background(), "/test", nil); err != nil {
		t.Fatalf("unexpected error from get: %v", err)
	}

	if gotAuth != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer test-token")
	}
}

func TestAPIClient_PostErrorStatus(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"broken"}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.post(context.Background(), "/fail", nil, nil)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should mention 500: %v", err)
	}
}

func TestAPIClient_Post204NoContent(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.post(context.Background(), "/ok", nil, nil)
	if err != nil {
		t.Fatalf("204 should not be an error: %v", err)
	}
}

func TestAPIClient_PostSetsContentType(t *testing.T) {
	var gotCT string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	body := strings.NewReader(`{"key":"value"}`)
	err := c.post(context.Background(), "/test", body, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotCT)
	}
}

func TestAPIClient_PostNilBodyNoContentType(t *testing.T) {
	var gotCT string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.post(context.Background(), "/test", nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotCT != "" {
		t.Fatalf("Content-Type = %q, want empty for nil body", gotCT)
	}
}

func TestAPIClient_PostWithBodyAndDst(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back a JSON response.
		reqBody, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"echo": string(reqBody)})
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	body := strings.NewReader(`{"type":"full"}`)
	var dst map[string]string
	err := c.post(context.Background(), "/test", body, &dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst["echo"] != `{"type":"full"}` {
		t.Fatalf("dst[echo] = %q, want request body echoed back", dst["echo"])
	}
}

func TestAPIClient_Put200WithBody(t *testing.T) {
	var gotMethod, gotCT string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	var dst map[string]string
	err := c.put(context.Background(), "/test", strings.NewReader(`{"key":"val"}`), &dst)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Fatalf("method = %q, want PUT", gotMethod)
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotCT)
	}
	if dst["status"] != "ok" {
		t.Fatalf("dst[status] = %q, want %q", dst["status"], "ok")
	}
}

func TestAPIClient_Put204NoDecodeAttempt(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	var dst map[string]string
	err := c.put(context.Background(), "/test", nil, &dst)
	if err != nil {
		t.Fatalf("204 with non-nil dst should not error: %v", err)
	}
	if dst != nil {
		t.Fatal("dst should remain nil on 204")
	}
}

func TestAPIClient_PutRedirectNotFollowed(t *testing.T) {
	var redirectHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.put(context.Background(), "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error for 302 redirect")
	}
	if redirectHit.Load() {
		t.Fatal("redirect target should not have been contacted")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("error should mention 302: %v", err)
	}
	if !strings.Contains(err.Error(), target.URL) {
		t.Fatalf("error should include redirect Location URL: %v", err)
	}
}

func TestAPIClient_PutErrorStatus(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"broken"}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.put(context.Background(), "/fail", nil, nil)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error should mention 500: %v", err)
	}
}

func TestAPIClient_RedirectNotFollowed_Get(t *testing.T) {
	var redirectHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.get(context.Background(), "/test", nil)
	if err == nil {
		t.Fatal("expected error for 302 redirect")
	}
	if redirectHit.Load() {
		t.Fatal("redirect target should not have been contacted")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("error should mention 302: %v", err)
	}
	if !strings.Contains(err.Error(), target.URL) {
		t.Fatalf("error should include redirect Location URL %q: %v", target.URL, err)
	}
}

func TestAPIClient_RedirectNotFollowed_Post(t *testing.T) {
	var redirectHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.post(context.Background(), "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error for 302 redirect")
	}
	if redirectHit.Load() {
		t.Fatal("redirect target should not have been contacted")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("error should mention 302: %v", err)
	}
	if !strings.Contains(err.Error(), target.URL) {
		t.Fatalf("error should include redirect Location URL %q: %v", target.URL, err)
	}
}

func TestAPIClient_GetInvalidJSON(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	var node NodeInfo
	err := c.get(context.Background(), "/bad", &node)
	if err == nil {
		t.Fatal("expected decode error")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Fatalf("error should mention decode: %v", err)
	}
}

// ---------- Dynamic sidebar tests ----------

func TestSidebar_ShowsPluginNames(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `href="/update"`) {
		t.Error("sidebar should contain link to /update")
	}
	if !strings.Contains(body, `href="/network"`) {
		t.Error("sidebar should contain link to /network")
	}
	if !strings.Contains(body, `href="/"`) {
		t.Error("sidebar should contain link to dashboard")
	}
	if !strings.Contains(body, `href="/firewall"`) {
		t.Error("sidebar should contain dynamic link to /firewall")
	}
}

// ---------- Generic plugin page tests ----------

func TestGenericPlugin_UnknownPlugin404(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown plugin, got %d", w.Code)
	}
}

func TestGenericPlugin_RendersForKnownPlugin(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{
				Name: "firewall", Version: "0.1.0",
				Description: "Firewall management",
				RoutePrefix: "/api/v1/plugins/firewall",
				Endpoints: []PluginEndpoint{
					{Method: "GET", Path: "/rules", Description: "Active firewall rules"},
					{Method: "POST", Path: "/reload", Description: "Reload firewall rules"},
				},
			},
		})
	})

	mux.HandleFunc("/api/v1/plugins/firewall/rules", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"rules": []string{"allow 22/tcp", "allow 80/tcp"},
		})
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Firewall") {
		t.Error("generic page should show plugin name")
	}
	if !strings.Contains(body, "Firewall management") {
		t.Error("generic page should show plugin description")
	}
	if !strings.Contains(body, "Active firewall rules") {
		t.Error("generic page should show endpoint description")
	}
	if !strings.Contains(body, "Reload firewall rules") {
		t.Error("generic page should show POST action button")
	}
	if strings.Contains(body, "/api/v1/plugins/firewall/reload") {
		t.Error("action button should NOT use direct API path")
	}
	if !strings.Contains(body, "/firewall/actions/reload") {
		t.Error("action button should use proxied web path")
	}
	if !strings.Contains(body, "allow 22/tcp") {
		t.Error("generic page should render fetched endpoint data")
	}
}

func TestGenericPlugin_RegistryUnavailable(t *testing.T) {
	// API server returns 500 for /api/v1/plugins → expect 502 Bad Gateway.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestGenericAction_RegistryUnavailable(t *testing.T) {
	// API server returns 500 for /api/v1/plugins → expect 502 Bad Gateway.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/firewall/actions/reload", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", w.Code)
	}
}

func TestGenericPlugin_EndpointError(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{
				Name: "metrics", Version: "0.1.0",
				Description: "System metrics",
				RoutePrefix: "/api/v1/plugins/metrics",
				Endpoints: []PluginEndpoint{
					{Method: "GET", Path: "/cpu", Description: "CPU usage"},
				},
			},
		})
	})

	mux.HandleFunc("/api/v1/plugins/metrics/cpu", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even with endpoint error, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Failed to fetch") {
		t.Error("error card should show failure message")
	}
}

// ---------- Generic action proxy tests ----------

func TestGenericAction_ProxiesPost(t *testing.T) {
	var gotPath string
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{
				Name: "firewall", Version: "0.1.0",
				Description: "Firewall management",
				RoutePrefix: "/api/v1/plugins/firewall",
				Endpoints: []PluginEndpoint{
					{Method: "POST", Path: "/reload", Description: "Reload rules"},
				},
			},
		})
	})

	mux.HandleFunc("/api/v1/plugins/firewall/reload", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/firewall/actions/reload", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotPath != "/api/v1/plugins/firewall/reload" {
		t.Fatalf("proxy should call API path, got %q", gotPath)
	}
	if !strings.Contains(w.Body.String(), "completed successfully") {
		t.Error("should show success message")
	}
}

func TestGenericAction_InvalidAction404(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{
				Name: "firewall", Version: "0.1.0",
				Description: "Firewall management",
				RoutePrefix: "/api/v1/plugins/firewall",
				Endpoints: []PluginEndpoint{
					{Method: "POST", Path: "/reload", Description: "Reload rules"},
				},
			},
		})
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/firewall/actions/delete", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for undeclared action, got %d", w.Code)
	}
}

func TestGenericAction_MultiSegmentPath(t *testing.T) {
	var gotPath string
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{
				Name: "firewall", Version: "0.1.0",
				Description: "Firewall management",
				RoutePrefix: "/api/v1/plugins/firewall",
				Endpoints: []PluginEndpoint{
					{Method: "POST", Path: "/rules/reload", Description: "Reload rules"},
				},
			},
		})
	})

	mux.HandleFunc("/api/v1/plugins/firewall/rules/reload", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/firewall/actions/rules/reload", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotPath != "/api/v1/plugins/firewall/rules/reload" {
		t.Fatalf("proxy should call multi-segment API path, got %q", gotPath)
	}
}

func TestGenericAction_PostAPIFailure(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{
				Name: "firewall", Version: "0.1.0",
				Description: "Firewall management",
				RoutePrefix: "/api/v1/plugins/firewall",
				Endpoints: []PluginEndpoint{
					{Method: "POST", Path: "/reload", Description: "Reload rules"},
				},
			},
		})
	})

	mux.HandleFunc("/api/v1/plugins/firewall/reload", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"backend failed"}`))
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/firewall/actions/reload", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Action failed") {
		t.Error("should show action failed message")
	}
}

func TestGenericPlugin_SkipsEmptyPathPOST(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{
				Name: "firewall", Version: "0.1.0",
				Description: "Firewall management",
				RoutePrefix: "/api/v1/plugins/firewall",
				Endpoints: []PluginEndpoint{
					{Method: "GET", Path: "/rules", Description: "Active rules"},
					{Method: "POST", Path: "", Description: "Empty path action"},
					{Method: "POST", Path: "/reload", Description: "Reload rules"},
				},
			},
		})
	})

	mux.HandleFunc("/api/v1/plugins/firewall/rules", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"rules": "allow 22"})
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Reload rules") {
		t.Error("valid POST action should appear")
	}
	if strings.Contains(body, "Empty path action") {
		t.Error("empty-path POST should be skipped")
	}
}

func TestGenericPlugin_SkipsTraversalPOSTPath(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{
				Name: "firewall", Version: "0.1.0",
				Description: "Firewall management",
				RoutePrefix: "/api/v1/plugins/firewall",
				Endpoints: []PluginEndpoint{
					{Method: "POST", Path: "/../../../etc/shadow", Description: "Traversal attack"},
					{Method: "POST", Path: "/reload", Description: "Reload rules"},
				},
			},
		})
	})

	mux.HandleFunc("/api/v1/plugins/firewall/rules", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{})
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "Traversal attack") {
		t.Error("traversal POST path should be skipped")
	}
	if !strings.Contains(body, "Reload rules") {
		t.Error("valid POST action should still appear")
	}
}

// ---------- Dashboard tests ----------

func TestDashboard_WithMockAPI(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"test-node", "Debian 12", "arm", "2d 5h 10m"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard should contain %q", want)
		}
	}
}

// ---------- Update plugin tests ----------

func TestUpdatePage_WithMockAPI(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"5", "2", "Security Update", "full", "completed"} {
		if !strings.Contains(body, want) {
			t.Errorf("update page should contain %q", want)
		}
	}
}

func TestUpdatePage_SecurityHiddenWhenUnavailable(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/plugins/update/status":
			json.NewEncoder(w).Encode([]PendingUpdate{
				{Package: "vim", CurrentVersion: "9.0.1", NewVersion: "9.0.2"},
			})
		case "/api/v1/plugins/update/logs":
			json.NewEncoder(w).Encode(RunStatus{})
		case "/api/v1/plugins/update/config":
			json.NewEncoder(w).Encode(UpdateConfig{SecurityAvailable: boolPtr(false)})
		}
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "Run Security Update") {
		t.Fatal("security update button should be hidden when unavailable")
	}
	if strings.Contains(w.Body.String(), "Auto Security Updates") {
		t.Fatal("auto_security form field should be hidden when unavailable")
	}
	if strings.Contains(w.Body.String(), "Security Source") {
		t.Fatal("security_source form field should be hidden when unavailable")
	}
}

func TestUpdatePage_SecurityShownWhenAvailable(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/plugins/update/status":
			json.NewEncoder(w).Encode([]PendingUpdate{
				{Package: "vim", CurrentVersion: "9.0.1", NewVersion: "9.0.2"},
			})
		case "/api/v1/plugins/update/logs":
			json.NewEncoder(w).Encode(RunStatus{})
		case "/api/v1/plugins/update/config":
			json.NewEncoder(w).Encode(UpdateConfig{SecurityAvailable: boolPtr(true)})
		}
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Run Security Update") {
		t.Fatal("security update button should be visible when available")
	}
	if !strings.Contains(body, "Auto Security Updates") {
		t.Fatal("auto_security form field should be visible when available")
	}
	if !strings.Contains(body, "Security Source") {
		t.Fatal("security_source form field should be visible when available")
	}
}

func TestUpdatePage_SecurityHiddenWhenNil(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/plugins/update/status":
			json.NewEncoder(w).Encode([]PendingUpdate{
				{Package: "vim", CurrentVersion: "9.0.1", NewVersion: "9.0.2"},
			})
		case "/api/v1/plugins/update/logs":
			json.NewEncoder(w).Encode(RunStatus{})
		case "/api/v1/plugins/update/config":
			// SecurityAvailable omitted → nil (fail-closed).
			json.NewEncoder(w).Encode(UpdateConfig{})
		}
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "Run Security Update") {
		t.Fatal("security update button should be hidden when SecurityAvailable is nil")
	}
	if strings.Contains(body, "Auto Security Updates") {
		t.Fatal("auto_security form field should be hidden when SecurityAvailable is nil")
	}
	if strings.Contains(body, "Security Source") {
		t.Fatal("security_source form field should be hidden when SecurityAvailable is nil")
	}
}

func TestUpdatePage_PartialAPIFailure(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/plugins/update/status":
			json.NewEncoder(w).Encode([]PendingUpdate{
				{Package: "vim", CurrentVersion: "9.0.1", NewVersion: "9.0.2"},
			})
		case "/api/v1/plugins/update/logs":
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/v1/plugins/update/config":
			json.NewEncoder(w).Encode(UpdateConfig{SecurityAvailable: boolPtr(true), Schedule: "0 3 * * *"})
		}
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Pending Updates") {
		t.Fatal("pending updates section should render with partial failure")
	}
	if !strings.Contains(body, "0 3 * * *") {
		t.Fatal("config should render with partial failure")
	}
}

func TestUpdateRun_Success(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/update/run", strings.NewReader("type=full"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("HX-Refresh") != "true" {
		t.Fatal("should set HX-Refresh header on success")
	}
}

func TestUpdateRun_APIError(t *testing.T) {
	h := newTestHandler(t, "http://localhost:1", "")
	req := httptest.NewRequest(http.MethodPost, "/update/run", strings.NewReader("type=full"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to start") {
		t.Fatal("should show error message")
	}
}

func TestUpdateRun_SecurityType(t *testing.T) {
	var gotPath string
	var gotBody string
	var gotMethod string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/update/run",
		strings.NewReader("type=security"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("API method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/plugins/update/run" {
		t.Fatalf("API path = %q, want /api/v1/plugins/update/run", gotPath)
	}
	if !strings.Contains(gotBody, `"type":"security"`) {
		t.Fatalf("API body = %q, want JSON with type:security", gotBody)
	}
	if w.Header().Get("HX-Refresh") != "true" {
		t.Fatal("should set HX-Refresh header on success")
	}
}

func TestUpdateRun_DefaultType(t *testing.T) {
	var gotPath string
	var gotBody string
	var gotMethod string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/update/run", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("API method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/plugins/update/run" {
		t.Fatalf("API path = %q, want /api/v1/plugins/update/run", gotPath)
	}
	if !strings.Contains(gotBody, `"type":"full"`) {
		t.Fatalf("API body = %q, want JSON with type:full", gotBody)
	}
	if w.Header().Get("HX-Refresh") != "true" {
		t.Fatal("should set HX-Refresh header on success")
	}
}

func TestUpdateRun_XSSSanitized(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/update/run",
		strings.NewReader("type=<script>alert(1)</script>"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("XSS payload should not appear in response")
	}
	if w.Header().Get("HX-Refresh") != "true" {
		t.Fatal("invalid type should default to full and set HX-Refresh")
	}
}

// ---------- Network plugin tests ----------

func TestNetworkPage_WithMockAPI(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/network", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"eth0", "192.168.1.10/24", "Online", "1.1.1.1"} {
		if !strings.Contains(body, want) {
			t.Errorf("network page should contain %q", want)
		}
	}
}

// ---------- Update settings tests ----------

func TestUpdateSettings_HappyPath(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("schedule=0+4+*+*+*&schedule_original=0+3+*+*+*&auto_security=true&auto_security_original=false&security_source=always&security_source_original=detected")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Settings updated successfully") {
		t.Errorf("expected success message, got %q", w.Body.String())
	}
	if w.Header().Get("HX-Refresh") != "true" {
		t.Error("should set HX-Refresh header on successful settings save")
	}
}

func TestUpdateSettings_SingleField(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("schedule=0+5+*+*+*&schedule_original=0+3+*+*+*")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Settings updated successfully") {
		t.Errorf("expected success, got %q", w.Body.String())
	}
	if w.Header().Get("HX-Refresh") != "true" {
		t.Error("should set HX-Refresh header on successful settings save")
	}
}

func TestUpdateSettings_ScheduleUnchangedSkipped(t *testing.T) {
	var putCalls atomic.Int32
	var receivedKeys []string
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		putCalls.Add(1)
		var payload struct {
			Key   string `json:"key"`
			Value any    `json:"value"`
		}
		json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		receivedKeys = append(receivedKeys, payload.Key)
		mu.Unlock()
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config: map[string]any{"key": "val"},
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	// schedule unchanged: value matches original; auto_security changed (original differs)
	body := strings.NewReader("schedule=0+3+*+*+*&schedule_original=0+3+*+*+*&auto_security=true&auto_security_original=false")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Settings updated successfully") {
		t.Errorf("expected success, got %q", w.Body.String())
	}
	// Only auto_security should have triggered a PUT, not schedule
	if got := putCalls.Load(); got != 1 {
		t.Errorf("expected 1 PUT call (auto_security only), got %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(receivedKeys) != 1 || receivedKeys[0] != "auto_security" {
		t.Errorf("expected only auto_security key, got %v", receivedKeys)
	}
}

func TestUpdateSettings_ScheduleChangedSent(t *testing.T) {
	var putCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		putCalls.Add(1)
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config: map[string]any{"key": "val"},
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	// schedule changed: value differs from original
	body := strings.NewReader("schedule=0+5+*+*+*&schedule_original=0+3+*+*+*")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Settings updated successfully") {
		t.Errorf("expected success, got %q", w.Body.String())
	}
	if got := putCalls.Load(); got != 1 {
		t.Errorf("expected 1 PUT call (schedule), got %d", got)
	}
}

func TestUpdateSettings_ScheduleCleared(t *testing.T) {
	type keyVal struct {
		Key   string `json:"key"`
		Value any    `json:"value"`
	}
	var received []keyVal
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload keyVal
		json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		received = append(received, payload)
		mu.Unlock()
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config: map[string]any{"key": "val"},
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	// schedule cleared: empty value but original was non-empty
	body := strings.NewReader("schedule=&schedule_original=0+3+*+*+*")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Settings updated successfully") {
		t.Errorf("expected success, got %q", w.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 PUT call, got %d", len(received))
	}
	if received[0].Key != "schedule" {
		t.Errorf("expected schedule key, got %q", received[0].Key)
	}
	if received[0].Value != "" {
		t.Errorf("expected empty schedule value for clearing, got %v", received[0].Value)
	}
}

func TestUpdateSettings_AllFieldsUnchanged(t *testing.T) {
	var putCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		putCalls.Add(1)
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config: map[string]any{"key": "val"},
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	// All fields match their originals — no PUTs should fire
	body := strings.NewReader("schedule=0+3+*+*+*&schedule_original=0+3+*+*+*&auto_security=true&auto_security_original=true&security_source=always&security_source_original=always")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No valid settings provided") {
		t.Errorf("expected no changes message, got %q", w.Body.String())
	}
	if got := putCalls.Load(); got != 0 {
		t.Errorf("expected 0 PUT calls for unchanged fields, got %d", got)
	}
}

func TestUpdateSettings_SelectUnchangedSkipped(t *testing.T) {
	var receivedKeys []string
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Key   string `json:"key"`
			Value any    `json:"value"`
		}
		json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		receivedKeys = append(receivedKeys, payload.Key)
		mu.Unlock()
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config: map[string]any{"key": "val"},
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	// auto_security and security_source unchanged; only schedule changed
	body := strings.NewReader("schedule=0+5+*+*+*&schedule_original=0+3+*+*+*&auto_security=true&auto_security_original=true&security_source=always&security_source_original=always")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Settings updated successfully") {
		t.Errorf("expected success, got %q", w.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(receivedKeys) != 1 || receivedKeys[0] != "schedule" {
		t.Errorf("expected only schedule key, got %v", receivedKeys)
	}
}

func TestUpdateSettings_BackwardCompatNoOriginals(t *testing.T) {
	var receivedKeys []string
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Key   string `json:"key"`
			Value any    `json:"value"`
		}
		json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		receivedKeys = append(receivedKeys, payload.Key)
		mu.Unlock()
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config: map[string]any{"key": "val"},
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	// No _original fields — backward compat: all valid fields should be sent
	body := strings.NewReader("schedule=0+3+*+*+*&auto_security=true&security_source=always")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Settings updated successfully") {
		t.Errorf("expected success, got %q", w.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	// Without _original fields, all 3 should be sent (schedule differs from empty original,
	// auto_security and security_source have empty original → orig=="" triggers send)
	if len(receivedKeys) != 3 {
		t.Errorf("expected 3 PUT calls without _original fields, got %d: %v", len(receivedKeys), receivedKeys)
	}
}

func TestUpdateSettings_NoValidFields(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("schedule=&auto_security=maybe&security_source=invalid")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (htmx fragment), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No valid settings provided") {
		t.Errorf("expected validation error, got %q", w.Body.String())
	}
}

func TestUpdateSettings_InvalidAutoSecurity(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("auto_security=yes")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No valid settings provided") {
		t.Errorf("invalid auto_security value should be rejected, got %q", w.Body.String())
	}
}

func TestUpdateSettings_InvalidSecuritySource(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("security_source=custom")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No valid settings provided") {
		t.Errorf("invalid security_source should be rejected, got %q", w.Body.String())
	}
}

func TestUpdateSettings_APIError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("schedule=0+3+*+*+*&schedule_original=0+5+*+*+*")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to save settings") {
		t.Errorf("expected error message, got %q", w.Body.String())
	}
}

func TestUpdateSettings_XSSSanitized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `<script>alert("xss")</script>`, http.StatusInternalServerError)
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("schedule=0+3+*+*+*&schedule_original=0+5+*+*+*")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	resp := w.Body.String()
	if strings.Contains(resp, "<script>") {
		t.Fatal("XSS payload should not appear unescaped")
	}
	if !strings.Contains(resp, "Failed to save settings") {
		t.Errorf("should use generic error message, got %q", resp)
	}
}

func TestUpdateSettings_WarningIncluded(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config:  map[string]any{"schedule": "0 3 * * *"},
			Warning: "cron daemon not running",
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("schedule=0+3+*+*+*&schedule_original=0+5+*+*+*")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, "Settings updated successfully") {
		t.Errorf("expected success, got %q", respBody)
	}
	if !strings.Contains(respBody, "cron daemon not running") {
		t.Errorf("expected warning, got %q", respBody)
	}
}

func TestUpdateSettings_WarningSanitized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config:  map[string]any{"schedule": "0 3 * * *"},
			Warning: `<img src=x onerror=alert(1)>`,
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("schedule=0+3+*+*+*&schedule_original=0+5+*+*+*")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	respBody := w.Body.String()
	if strings.Contains(respBody, "<img") {
		t.Fatal("XSS payload in warning should be escaped")
	}
	if !strings.Contains(respBody, "&lt;img") {
		t.Fatal("warning should contain escaped img tag")
	}
}

func TestUpdatePage_ShowsEditForm(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	for _, want := range []string{
		"Edit Settings",
		`name="schedule"`,
		`type="hidden" name="schedule_original"`,
		`type="hidden" name="auto_security_original"`,
		`type="hidden" name="security_source_original"`,
		`name="auto_security"`,
		`name="security_source"`,
		"Save Settings",
		"0 3 * * *",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("edit form should contain %q", want)
		}
	}
}

func TestUpdateSettings_AutoSecurityFalse(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("auto_security=false&auto_security_original=true")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected text/html Content-Type, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "Settings updated successfully") {
		t.Errorf("auto_security=false should be accepted, got %q", w.Body.String())
	}
}

func TestUpdateSettings_EmptyBody(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (htmx fragment), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "No valid settings provided") {
		t.Errorf("empty body should be rejected, got %q", w.Body.String())
	}
}

func TestUpdateSettings_ContentTypeOnError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("schedule=test&schedule_original=old")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("error response should have text/html Content-Type, got %q", ct)
	}
}

func TestUpdateSettings_PartialFailure(t *testing.T) {
	var callCount atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		n := callCount.Add(1)
		if n == 2 {
			// Second call fails
			http.Error(w, "backend error", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(PluginSettingsUpdateResult{
			Config: map[string]any{"key": "val"},
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	body := strings.NewReader("schedule=0+3+*+*+*&schedule_original=0+5+*+*+*&auto_security=true&auto_security_original=false&security_source=always&security_source_original=detected")
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	// Partial failure: some succeeded, some failed
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for partial failure, got %d", w.Code)
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, "Updated") {
		t.Errorf("should mention updated keys, got %q", respBody)
	}
	if !strings.Contains(respBody, "failed to update") {
		t.Errorf("should mention failed keys, got %q", respBody)
	}
	if got := w.Header().Get("HX-Refresh"); got != "" {
		t.Errorf("partial failure must not set HX-Refresh, got %q", got)
	}
}

func TestUpdateSettings_ValidationStatusCodes(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")

	tests := []struct {
		name       string
		body       string
		wantCode   int
		wantString string
	}{
		{"invalid auto_security", "auto_security=yes", http.StatusOK, "No valid settings"},
		{"invalid security_source", "security_source=custom", http.StatusOK, "No valid settings"},
		{"valid schedule", "schedule=0+3+*+*+*&schedule_original=old", http.StatusOK, "Settings updated"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/update/settings", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			h.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected %d, got %d", tt.wantCode, w.Code)
			}
			if !strings.Contains(w.Body.String(), tt.wantString) {
				t.Errorf("expected %q in response, got %q", tt.wantString, w.Body.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// friendlyAPIError extraction tests
// ---------------------------------------------------------------------------

func TestFriendlyAPIError_EnvelopeExtracted(t *testing.T) {
	body := []byte(`{"error":{"code":"job_not_found","message":"Job 'update.security' not found","details":{}}}`)
	err := friendlyAPIError("GET", "/test", 404, body)
	if err == nil {
		t.Fatal("expected error")
	}
	want := "Job 'update.security' not found"
	if err.Error() != want {
		t.Errorf("got %q, want %q", err.Error(), want)
	}
}

func TestFriendlyAPIError_PlainBodyFallback(t *testing.T) {
	body := []byte(`not json`)
	err := friendlyAPIError("GET", "/test", 500, body)
	if !strings.Contains(err.Error(), "not json") {
		t.Errorf("expected raw body in fallback, got %q", err.Error())
	}
}

func TestFriendlyAPIError_EmptyMessage(t *testing.T) {
	body := []byte(`{"error":{"code":"unknown","message":""}}`)
	err := friendlyAPIError("GET", "/test", 500, body)
	// Empty message → fallback to full body
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("expected fallback with body, got %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// API client integration: verify friendly errors via HTTP error methods
// ---------------------------------------------------------------------------

func TestAPIClient_GetFriendlyError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"not_found","message":"resource not found"}}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	var dst map[string]any
	err := c.get(context.Background(), "/test", &dst)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "resource not found" {
		t.Errorf("want friendly message, got %q", err.Error())
	}
}

func TestAPIClient_PostFriendlyError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"code":"invalid","message":"bad schedule"}}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.post(context.Background(), "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "bad schedule" {
		t.Errorf("want friendly message, got %q", err.Error())
	}
}

func TestAPIClient_PutFriendlyError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"error":{"code":"validation","message":"invalid value"}}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.put(context.Background(), "/test", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "invalid value" {
		t.Errorf("want friendly message, got %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Cron validation tests
// ---------------------------------------------------------------------------

func TestValidateWebCronExpr_ValidFormats(t *testing.T) {
	valid := []string{
		"",             // empty = clear schedule
		"0 3 * * *",    // standard 5-field
		"*/15 * * * *", // step values
		"0 0 * * 1-5",  // range
		"@daily",       // lowercase shortcut
		"@Weekly",      // mixed case
		"@HOURLY",      // uppercase
		"@annually",
		"@midnight",
		"@monthly",
		"@yearly",
	}
	for _, expr := range valid {
		if err := validateWebCronExpr(expr); err != nil {
			t.Errorf("expected %q to be valid, got: %v", expr, err)
		}
	}
}

func TestValidateWebCronExpr_InvalidFormats(t *testing.T) {
	invalid := []string{
		"0 2 * * * MON", // 6-field Quartz
		"* * * * * * *", // 7-field
		"not-a-cron",    // garbage (1 field)
		"0 2 *",         // 3 fields
	}
	for _, expr := range invalid {
		if err := validateWebCronExpr(expr); err == nil {
			t.Errorf("expected %q to be invalid", expr)
		}
	}
}

func TestValidateWebCronExpr_SixFieldErrorMessage(t *testing.T) {
	err := validateWebCronExpr("0 2 * * * MON")
	if err == nil {
		t.Fatal("expected error for 6-field expression")
	}
	if !strings.Contains(err.Error(), "got 6") {
		t.Errorf("error should mention 6 fields: %v", err)
	}
	if !strings.Contains(err.Error(), "seconds field") {
		t.Errorf("error should hint about seconds field: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Integration: cron validation rejects bad schedule in handleUpdateSettings
// ---------------------------------------------------------------------------

func TestUpdateSettings_InvalidCronRejected(t *testing.T) {
	// API should never be called because validation rejects the schedule.
	apiCalled := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, _ *http.Request) {
		apiCalled = true
		w.WriteHeader(http.StatusOK)
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := url.Values{
		"schedule":          {"0 2 * * * MON"}, // 6-field
		"schedule_original": {"0 3 * * *"},     // different → change detected
	}
	body := strings.NewReader(form.Encode())
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (htmx swap), got %d: %s", w.Code, w.Body.String())
	}
	if apiCalled {
		t.Error("API should not have been called for invalid cron")
	}
	if !strings.Contains(w.Body.String(), "got 6") {
		t.Errorf("response should mention field count: %s", w.Body.String())
	}
}

func TestUpdateSettings_ShortcutScheduleAccepted(t *testing.T) {
	apiCalled := false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/plugins/update/settings", func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		var payload struct {
			Key   string `json:"key"`
			Value any    `json:"value"`
		}
		json.NewDecoder(r.Body).Decode(&payload)
		if payload.Key != "schedule" {
			t.Errorf("expected key=schedule, got %q", payload.Key)
		}
		if payload.Value != "@daily" {
			t.Errorf("expected value=@daily, got %v", payload.Value)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := url.Values{
		"schedule":          {"@daily"},
		"schedule_original": {"0 3 * * *"},
	}
	body := strings.NewReader(form.Encode())
	req := httptest.NewRequest(http.MethodPost, "/update/settings", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code >= 400 {
		t.Fatalf("expected success, got %d: %s", w.Code, w.Body.String())
	}
	if !apiCalled {
		t.Error("API settings endpoint should have been called")
	}
}
