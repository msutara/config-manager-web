package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

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
			SecurityAvailable:  true,
			AutoSecurityUpdate: true,
			Schedule:           "0 3 * * *",
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
			json.NewEncoder(w).Encode(UpdateConfig{SecurityAvailable: false})
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
			json.NewEncoder(w).Encode(UpdateConfig{SecurityAvailable: true, Schedule: "0 3 * * *"})
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
