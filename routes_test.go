package web

import (
	"bytes"
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

// assertSettingsRedirect checks that a successful settings save returns an
// HX-Redirect with the expected flash param and an empty body.
func assertSettingsRedirect(t *testing.T, w *httptest.ResponseRecorder, flash string) {
	t.Helper()
	redir := w.Header().Get("HX-Redirect")
	want := "/update?flash=" + flash
	if redir != want {
		t.Errorf("expected HX-Redirect %q, got %q", want, redir)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("expected empty body on redirect, got %q", body)
	}
}

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
			Duration:  "2m 15s",
			Packages:  3,
			Log:       "Updating openssl 3.0.1 -> 3.0.2\nUpdating curl 7.88.0 -> 7.88.1\nDone.",
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

	mux.HandleFunc("/api/v1/jobs/trigger", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
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
	err := c.post(context.Background(), "/api/v1/jobs/trigger", nil, nil)
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

func TestAPIClient_OversizedResponseRejected(t *testing.T) {
	// Serve a JSON response larger than maxResponseBytes for every path.
	// Payload is derived from the constant so the test stays valid if the limit changes.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"hostname":"`))
		payloadSize := int(maxResponseBytes) + 1024
		chunk := bytes.Repeat([]byte("x"), 64*1024)
		for written := 0; written < payloadSize; written += len(chunk) {
			remaining := payloadSize - written
			if remaining < len(chunk) {
				w.Write(chunk[:remaining])
				break
			}
			w.Write(chunk)
		}
		w.Write([]byte(`"}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")

	cases := []struct {
		name string
		fn   func() error
	}{
		{"get", func() error {
			var n NodeInfo
			return c.get(context.Background(), "/huge", &n)
		}},
		{"post", func() error {
			var n NodeInfo
			return c.post(context.Background(), "/huge", nil, &n)
		}},
		{"put", func() error {
			var n NodeInfo
			return c.put(context.Background(), "/huge", nil, &n)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			if err == nil {
				t.Fatal("expected error for oversized response")
			}
			if !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("error should mention size limit exceeded: %v", err)
			}
		})
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
		t.Error("generic page should show plugin title")
	}
	if !strings.Contains(body, `hx-get="/fragments/firewall"`) {
		t.Error("generic page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("generic page should contain skeleton placeholders")
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
	// Page now shows skeleton, not data — endpoint errors appear in the fragment.
	if !strings.Contains(body, `hx-get="/fragments/metrics"`) {
		t.Error("page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("page should contain skeleton placeholders")
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

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (htmx fragment), got %d", w.Code)
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
	// Page now shows skeleton; actions are in the fragment.
	if !strings.Contains(body, `hx-get="/fragments/firewall"`) {
		t.Error("page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("page should contain skeleton placeholders")
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
	// Page now shows skeleton; actions are in the fragment.
	if !strings.Contains(body, `hx-get="/fragments/firewall"`) {
		t.Error("page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("page should contain skeleton placeholders")
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
	// Page now shows skeleton; data loads via fragment.
	if !strings.Contains(body, `hx-get="/fragments/dashboard"`) {
		t.Error("dashboard should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("dashboard should contain skeleton placeholders")
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
	// Page now shows skeleton; data loads via fragment.
	if !strings.Contains(body, `hx-get="/fragments/update"`) {
		t.Error("update page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("update page should contain skeleton placeholders")
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
		case "/api/v1/plugins":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v1/node":
			json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
		default:
			http.NotFound(w, r)
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
	// Page now shows skeleton; security visibility is in the fragment.
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/update"`) {
		t.Error("update page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("update page should contain skeleton placeholders")
	}
}

func TestUpdatePage_EmptyPendingHidesTable(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/plugins/update/status":
			json.NewEncoder(w).Encode([]PendingUpdate{})
		case "/api/v1/plugins/update/logs":
			json.NewEncoder(w).Encode(RunStatus{Type: "full", Status: "completed"})
		case "/api/v1/plugins/update/config":
			json.NewEncoder(w).Encode(UpdateConfig{SecurityAvailable: boolPtr(true)})
		case "/api/v1/plugins":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v1/node":
			json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
		default:
			http.NotFound(w, r)
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
	// Page now shows skeleton; table visibility is in the fragment.
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/update"`) {
		t.Error("update page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("update page should contain skeleton placeholders")
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
	// Page now shows skeleton; security button visibility is in the fragment.
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/update"`) {
		t.Error("update page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("update page should contain skeleton placeholders")
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
	// Page now shows skeleton; security button visibility is in the fragment.
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/update"`) {
		t.Error("update page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("update page should contain skeleton placeholders")
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
	// Page now shows skeleton; partial failure rendering is in the fragment.
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/update"`) {
		t.Error("update page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("update page should contain skeleton placeholders")
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
	body := w.Body.String()
	if !strings.Contains(body, "update.full") {
		t.Fatal("should return progress fragment with job ID")
	}
	if !strings.Contains(body, "progress") {
		t.Fatal("should contain progress polling element")
	}
}

func TestUpdateRun_APIError(t *testing.T) {
	h := newTestHandler(t, "http://localhost:1", "")
	req := httptest.NewRequest(http.MethodPost, "/update/run", strings.NewReader("type=full"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Failed to start") {
		t.Fatal("should show error message")
	}
	if !strings.Contains(body, "alert-error") {
		t.Fatal("should render error alert fragment")
	}
	if !strings.Contains(body, `hx-swap-oob`) {
		t.Error("error should include OOB toast")
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
	if gotPath != "/api/v1/jobs/trigger" {
		t.Fatalf("API path = %q, want /api/v1/jobs/trigger", gotPath)
	}
	if !strings.Contains(gotBody, `"job_id":"update.security"`) {
		t.Fatalf("API body = %q, want JSON with job_id:update.security", gotBody)
	}
	body := w.Body.String()
	if !strings.Contains(body, "update.security") {
		t.Fatal("should return progress fragment with security job ID")
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
	if gotPath != "/api/v1/jobs/trigger" {
		t.Fatalf("API path = %q, want /api/v1/jobs/trigger", gotPath)
	}
	if !strings.Contains(gotBody, `"job_id":"update.full"`) {
		t.Fatalf("API body = %q, want JSON with job_id:update.full", gotBody)
	}
	body := w.Body.String()
	if !strings.Contains(body, "update.full") {
		t.Fatal("should return progress fragment with full job ID")
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
	if !strings.Contains(w.Body.String(), "update.full") {
		t.Fatal("invalid type should default to full and return progress")
	}
}

// ---------- Job progress tests ----------

func TestProgress_RunningJob(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/jobs/update.full/runs/latest" {
			json.NewEncoder(w).Encode(JobRun{
				JobID:     "update.full",
				Status:    "running",
				StartedAt: "2026-03-06T12:00:00Z",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "every 2s") {
		t.Fatal("running job should include HTMX polling trigger")
	}
	if !strings.Contains(body, "update.full") {
		t.Fatal("should show job ID")
	}
	if !strings.Contains(body, "progress-box") {
		t.Fatal("should render progress box")
	}
}

func TestProgress_CompletedJob(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/jobs/update.security/runs/latest" {
			json.NewEncoder(w).Encode(JobRun{
				JobID:    "update.security",
				Status:   "completed",
				Duration: "45s",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.security", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// Completed jobs return HX-Redirect instead of rendering a fragment.
	redirect := w.Header().Get("HX-Redirect")
	if redirect != "/update" {
		t.Fatalf("expected HX-Redirect /update, got %q", redirect)
	}
	if body := w.Body.String(); body != "" {
		t.Fatalf("expected empty body for redirect, got %q", body)
	}
}

func TestProgress_CompletedJobCustomReturn(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/jobs/network.scan/runs/latest" {
			json.NewEncoder(w).Encode(JobRun{
				JobID:  "network.scan",
				Status: "completed",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=network.scan&return=/network", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	redirect := w.Header().Get("HX-Redirect")
	if redirect != "/network" {
		t.Fatalf("expected HX-Redirect /network, got %q", redirect)
	}
}

func TestProgress_CompletedJobWithError(t *testing.T) {
	// Even if the API returns completed with an error message, the handler
	// should still redirect (the error is informational, not terminal).
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/jobs/update.full/runs/latest" {
			json.NewEncoder(w).Encode(JobRun{
				JobID:  "update.full",
				Status: "completed",
				Error:  "partial failure: 2 packages skipped",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&return=/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	redirect := w.Header().Get("HX-Redirect")
	if redirect != "/update" {
		t.Fatalf("expected HX-Redirect /update, got %q", redirect)
	}
	if body := w.Body.String(); body != "" {
		t.Fatalf("expected empty body for redirect, got %q", body)
	}
}

func TestProgress_FailedJob(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/jobs/network.scan/runs/latest" {
			json.NewEncoder(w).Encode(JobRun{
				JobID:    "network.scan",
				Status:   "failed",
				Duration: "3s",
				Error:    "job failed; see server logs",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=network.scan", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "failed") {
		t.Fatal("should show failed status")
	}
	if !strings.Contains(body, "alert-error") {
		t.Fatal("should render error alert")
	}
}

func TestProgress_InvalidJobID(t *testing.T) {
	h := newTestHandler(t, "http://localhost:1", "")

	cases := []string{
		"",
		"../etc/passwd",
		"no-dot",
		"UPPER.case",
		"update.full; rm -rf /",
	}
	for _, jobID := range cases {
		req := httptest.NewRequest(http.MethodGet, "/progress?job="+url.QueryEscape(jobID), nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("job=%q: expected 200, got %d", jobID, w.Code)
		}
		body := w.Body.String()
		if !strings.Contains(body, "alert-error") {
			t.Errorf("job=%q: expected error fragment, got %s", jobID, body)
		}
		// Error fragment must NOT contain hx-trigger (no retry for invalid IDs).
		if strings.Contains(body, "hx-trigger") {
			t.Errorf("job=%q: invalid job error should not retry", jobID)
		}
	}
}

func TestProgress_DefaultReturnURL(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(JobRun{
			JobID:  "network.scan",
			Status: "completed",
		})
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=network.scan", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Completed → HX-Redirect with derived return URL.
	redirect := w.Header().Get("HX-Redirect")
	if redirect != "/network" {
		t.Fatalf("expected HX-Redirect /network, got %q", redirect)
	}
}

func TestProgress_CustomReturnURL(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(JobRun{
			JobID:  "update.full",
			Status: "completed",
		})
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&return=/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Completed → HX-Redirect with explicit return URL.
	redirect := w.Header().Get("HX-Redirect")
	if redirect != "/update" {
		t.Fatalf("expected HX-Redirect /update, got %q", redirect)
	}
}

func TestProgress_APIError(t *testing.T) {
	// API that always returns 500 to trigger the error branch.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Failed to check job status") {
		t.Fatal("should show error when API fails")
	}
	if !strings.Contains(body, "alert-error") {
		t.Fatal("should render error alert")
	}
	// Error response must keep polling so transient failures recover.
	if !strings.Contains(body, "hx-trigger") {
		t.Fatal("error response must include hx-trigger for retry polling")
	}
	if !strings.Contains(body, "retrying") {
		t.Fatal("error response should indicate retry is happening")
	}
}

func TestProgress_APIError_NotRetryable(t *testing.T) {
	// API returns 404 — non-retryable; polling should stop.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"message":"job not found"}}`, http.StatusNotFound)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "alert-error") {
		t.Fatal("should render error alert for 404")
	}
	// Non-retryable errors must NOT keep polling.
	if strings.Contains(body, "hx-trigger") {
		t.Fatal("non-retryable 404 error must not include hx-trigger")
	}
	if strings.Contains(body, "retrying") {
		t.Fatal("non-retryable error should not say retrying")
	}
	if !strings.Contains(body, "failed") || !strings.Contains(body, "job not found") {
		t.Fatal("should show terminal failure with API message")
	}
}

func TestProgress_ErrorRetryCapExceeded(t *testing.T) {
	// API returns 500 (retryable) but retry count is at the cap (>= maxErrorRetries).
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&retry=30", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "too many retries") {
		t.Fatal("should show retry cap message")
	}
	// Must be terminal — no polling trigger.
	if strings.Contains(body, "hx-trigger") {
		t.Fatal("retry cap exceeded must not include hx-trigger")
	}
	if strings.Contains(body, "retrying") {
		t.Fatal("retry cap exceeded should not say retrying")
	}
}

func TestProgress_ErrorRetryCountIncremented(t *testing.T) {
	// API returns 500 (retryable) with retry=5 — should continue polling with retry=6.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&retry=5", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "retrying") {
		t.Fatal("should still be retrying under cap")
	}
	if !strings.Contains(body, "retry=6") {
		t.Fatal("retry count should be incremented to 6 in polling URL")
	}
	if !strings.Contains(body, "every 5s") {
		t.Fatal("error state should poll at 5s interval")
	}
}

func TestProgress_SuccessResetsRetryCount(t *testing.T) {
	// API returns running with retry param — retry count should reset.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(JobRun{
			JobID:  "update.full",
			Status: "running",
		})
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&retry=15", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "is running") {
		t.Fatal("should show running status")
	}
	// Successful poll should not carry retry count forward.
	if strings.Contains(body, "retry=") {
		t.Fatal("successful poll should not include retry param in URL")
	}
}

func TestProgress_ErrorRetryFirstError(t *testing.T) {
	// First error (no retry param) should increment to retry=1.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "retry=1") {
		t.Fatal("first error should set retry=1 in polling URL")
	}
	if !strings.Contains(body, "retrying") {
		t.Fatal("first error should show retrying message")
	}
}

func TestProgress_ErrorRetryNegativeClamped(t *testing.T) {
	// Negative retry value should be clamped to 0 and treated as first error.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&retry=-100", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "retry=1") {
		t.Fatal("negative retry should be clamped to 0, then incremented to 1")
	}
	if strings.Contains(body, "retry=-") {
		t.Fatal("negative retry value must not propagate")
	}
}

func TestProgress_ErrorRetryNonNumericClamped(t *testing.T) {
	// Non-numeric retry value causes a parse error and is treated as retry=0 by the handler.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&retry=abc", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "retry=1") {
		t.Fatal("non-numeric retry should default to 0, then increment to 1")
	}
}

func TestProgress_ErrorRetryBoundaryJustUnderCap(t *testing.T) {
	// retry=29 is just under the cap of 30 — should continue polling.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&retry=29", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "retry=30") {
		t.Fatal("retry=29 should increment to 30 in polling URL")
	}
	if !strings.Contains(body, "retrying") {
		t.Fatal("retry=29 should still be retrying (under cap)")
	}
	if strings.Contains(body, "too many retries") {
		t.Fatal("retry=29 should not trigger cap message")
	}
}

func TestProgress_ErrorRetryAboveCap(t *testing.T) {
	// retry=31 is above the cap — should stop polling.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&retry=31", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "too many retries") {
		t.Fatal("retry=31 (above cap) should show cap message")
	}
	if strings.Contains(body, "hx-trigger") {
		t.Fatal("above cap must not include polling trigger")
	}
}

func TestProgress_UnknownStatus(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(JobRun{
			JobID:  "update.full",
			Status: "queued",
		})
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "No run data available") {
		t.Fatal("unknown status should show fallback message")
	}
}

func TestProgress_ReturnURL_OpenRedirect(t *testing.T) {
	// Use "running" status so the template renders a body with hx-get;
	// completed returns HX-Redirect with no body.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(JobRun{
			JobID:  "update.full",
			Status: "running",
		})
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")

	dangerous := []string{
		"https://evil.com",
		"//evil.com",
		`/\evil.com`,
		"javascript:alert(1)",
		"data:text/html,<h1>pwned</h1>",
		"/update\r\nX-Injected: true",
		"/update\x00evil",
	}
	for _, u := range dangerous {
		req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&return="+url.QueryEscape(u), nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		body := w.Body.String()
		if strings.Contains(body, u) {
			t.Errorf("return=%q should be rejected, but found in response", u)
		}
		// The polling URL must carry return=%2F (i.e. "/") to prove the
		// handler sanitised the dangerous value back to the root.
		if !strings.Contains(body, `return=%2F"`) {
			t.Errorf("return=%q should fall back to '/' in polling URL, body=%s", u, body)
		}
	}
}

func TestProgress_ReturnURL_OpenRedirect_Completed(t *testing.T) {
	// Completed jobs get HX-Redirect; verify dangerous URLs are sanitised.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(JobRun{
			JobID:  "update.full",
			Status: "completed",
		})
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")

	dangerous := []string{
		"https://evil.com",
		"//evil.com",
		`/\evil.com`,
		"javascript:alert(1)",
		"data:text/html,<h1>pwned</h1>",
		"/update\r\nX-Injected: true",
		"/update\x00evil",
	}
	for _, u := range dangerous {
		req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&return="+url.QueryEscape(u), nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		redirect := w.Header().Get("HX-Redirect")
		if redirect != "/" {
			t.Errorf("return=%q should fall back to '/', got HX-Redirect=%q", u, redirect)
		}
	}
}

func TestProgress_ReturnURL_Propagated(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(JobRun{
			JobID:  "update.full",
			Status: "running",
		})
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/progress?job=update.full&return=/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	// The polling URL in the running fragment must carry the return param
	// and must use correct HTML entity encoding (single &amp;, not &amp;amp;).
	if !strings.Contains(body, "&amp;return=") {
		t.Fatal("running fragment must propagate return URL with correct &amp; encoding")
	}
	if strings.Contains(body, "&amp;amp;return=") {
		t.Fatal("return URL must not be double-encoded")
	}
	if !strings.Contains(body, "return=%2Fupdate") {
		t.Fatal("return URL must be URL-encoded in the polling query string")
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
	// Page now shows skeleton; data loads via fragment.
	if !strings.Contains(body, `hx-get="/fragments/network"`) {
		t.Error("network page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("network page should contain skeleton placeholders")
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
	assertSettingsRedirect(t, w, "settings-saved")
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
	assertSettingsRedirect(t, w, "settings-saved")
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
	assertSettingsRedirect(t, w, "settings-saved")
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
	assertSettingsRedirect(t, w, "settings-saved")
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
	assertSettingsRedirect(t, w, "settings-saved")
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
	assertSettingsRedirect(t, w, "settings-saved")
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
	assertSettingsRedirect(t, w, "settings-saved")
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
	if !strings.Contains(w.Body.String(), `hx-swap-oob`) {
		t.Error("validation error should include OOB toast")
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
	if !strings.Contains(w.Body.String(), `hx-swap-oob`) {
		t.Error("invalid auto_security rejection should include OOB toast")
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
	if !strings.Contains(w.Body.String(), `hx-swap-oob`) {
		t.Error("invalid security_source rejection should include OOB toast")
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

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (htmx fragment), got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to save settings") {
		t.Errorf("expected error message, got %q", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `hx-swap-oob`) {
		t.Error("API error should include OOB toast")
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

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (htmx fragment), got %d", w.Code)
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
	// Success with warnings redirects with settings-partial flash.
	assertSettingsRedirect(t, w, "settings-partial")
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
	// Success with warning redirects; sanitization is tested via the partial
	// failure path in TestUpdateSettings_PartialFailure instead.
	assertSettingsRedirect(t, w, "settings-partial")
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

	// Page now shows skeleton; edit form is in the fragment.
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/update"`) {
		t.Error("update page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("update page should contain skeleton placeholders")
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
	assertSettingsRedirect(t, w, "settings-saved")
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
	if !strings.Contains(w.Body.String(), `hx-swap-oob`) {
		t.Error("empty body rejection should include OOB toast")
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
			Config:  map[string]any{"key": "val"},
			Warning: `<img src=x onerror=alert(1)>`,
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
	if got := w.Header().Get("HX-Redirect"); got != "" {
		t.Errorf("partial failure must not set HX-Redirect, got %q", got)
	}
	if !strings.Contains(respBody, `hx-swap-oob`) {
		t.Error("partial failure should include OOB toast")
	}
	if strings.Contains(respBody, "<img") {
		t.Fatal("XSS payload in warning should be escaped in partial failure")
	}
	if !strings.Contains(respBody, "&lt;img") {
		t.Error("warning should contain escaped img tag in partial failure")
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
		wantString string // checked in body; empty means check HX-Redirect instead
		wantFlash  string // if non-empty, expect HX-Redirect with this flash
		wantToast  bool   // if true, expect hx-swap-oob in body
	}{
		{"invalid auto_security", "auto_security=yes", http.StatusOK, "No valid settings", "", true},
		{"invalid security_source", "security_source=custom", http.StatusOK, "No valid settings", "", true},
		{"valid schedule", "schedule=0+3+*+*+*&schedule_original=old", http.StatusOK, "", "settings-saved", false},
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
			if tt.wantFlash != "" {
				assertSettingsRedirect(t, w, tt.wantFlash)
			} else if !strings.Contains(w.Body.String(), tt.wantString) {
				t.Errorf("expected %q in response, got %q", tt.wantString, w.Body.String())
			}
			if tt.wantToast && !strings.Contains(w.Body.String(), `hx-swap-oob`) {
				t.Error("expected OOB toast in response")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// friendlyAPIError extraction tests
// ---------------------------------------------------------------------------

func TestFriendlyAPIError_EnvelopeExtracted(t *testing.T) {
	body := []byte(`{"error":{"code":"job_not_found","message":"Job 'update.security' not found","details":{}}}`)
	err := friendlyAPIError(404, body)
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
	err := friendlyAPIError(500, body)
	if !strings.Contains(err.Error(), "not json") {
		t.Errorf("expected raw body in fallback, got %q", err.Error())
	}
}

func TestFriendlyAPIError_EmptyMessage(t *testing.T) {
	body := []byte(`{"error":{"code":"unknown","message":""}}`)
	err := friendlyAPIError(500, body)
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
	if !strings.Contains(w.Body.String(), `hx-swap-oob`) {
		t.Error("invalid cron rejection should include OOB toast")
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

// ---------------------------------------------------------------------------
// Toast notification tests
// ---------------------------------------------------------------------------

func TestToastOOB_Format(t *testing.T) {
	got := toastOOB("success", "It worked!")
	if !strings.Contains(got, `hx-swap-oob="afterbegin:#toast-container"`) {
		t.Error("missing OOB swap attribute with selector")
	}
	if !strings.Contains(got, `toast-success`) {
		t.Error("missing toast level class")
	}
	if !strings.Contains(got, "It worked!") {
		t.Error("missing toast message")
	}
	if !strings.Contains(got, `role="status"`) {
		t.Error("missing ARIA role")
	}
}

func TestToastOOB_EscapesHTML(t *testing.T) {
	got := toastOOB("error", `<script>alert("xss")</script>`)
	if strings.Contains(got, "<script>") {
		t.Fatal("XSS payload should be escaped in toast")
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Error("expected escaped script tag")
	}
}

func TestToastOOB_SanitizesLevel(t *testing.T) {
	got := toastOOB(`"><script>xss</script><div class="`, "msg")
	if strings.Contains(got, "<script>") {
		t.Fatal("invalid level should be sanitized, not injected")
	}
	// Invalid level falls back to "error"
	if !strings.Contains(got, `toast-error`) {
		t.Error("invalid level should fall back to error")
	}
}

func TestToastOOB_ErrorUsesAlertRole(t *testing.T) {
	got := toastOOB("error", "Something failed")
	if !strings.Contains(got, `role="alert"`) {
		t.Error("error toasts should use role=alert for accessibility")
	}
}

func TestToastOOB_SuccessUsesStatusRole(t *testing.T) {
	got := toastOOB("success", "Done")
	if !strings.Contains(got, `role="status"`) {
		t.Error("success toasts should use role=status")
	}
}

func TestParseFlashToast_KnownValues(t *testing.T) {
	tests := []struct {
		flash   string
		level   string
		message string
	}{
		{"settings-saved", "success", "Settings saved successfully"},
		{"settings-partial", "warning", "Settings saved with warnings"},
		{"action-ok", "success", "Action completed successfully"},
	}
	for _, tt := range tests {
		t.Run(tt.flash, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/?flash="+tt.flash, nil)
			toast := parseFlashToast(req)
			if toast == nil {
				t.Fatal("expected toast, got nil")
			}
			if toast.Level != tt.level {
				t.Errorf("level: got %q, want %q", toast.Level, tt.level)
			}
			if toast.Message != tt.message {
				t.Errorf("message: got %q, want %q", toast.Message, tt.message)
			}
		})
	}
}

func TestParseFlashToast_UnknownValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?flash=nope", nil)
	if toast := parseFlashToast(req); toast != nil {
		t.Errorf("unknown flash should return nil, got %+v", toast)
	}
}

func TestParseFlashToast_Missing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if toast := parseFlashToast(req); toast != nil {
		t.Errorf("no flash param should return nil, got %+v", toast)
	}
}

func TestUpdatePage_FlashRendersToast(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/update?flash=settings-saved", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "toast-success") {
		t.Error("page with flash=settings-saved should render a success toast")
	}
	if !strings.Contains(body, "Settings saved successfully") {
		t.Error("page should contain flash toast message")
	}
}

func TestGenericAction_SuccessIncludesToast(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{{
			Name: "test", Description: "Test", RoutePrefix: "/api/v1/plugins/test",
			Endpoints: []PluginEndpoint{
				{Method: "POST", Path: "/run", Description: "Run test"},
			},
		}})
	})
	mux.HandleFunc("/api/v1/plugins/test/run", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/test/actions/run", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `hx-swap-oob`) {
		t.Error("success action should include OOB toast")
	}
	if !strings.Contains(body, `toast-success`) {
		t.Error("success action should include success toast class")
	}
}

func TestGenericAction_ErrorIncludesToast(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{{
			Name: "test", Description: "Test", RoutePrefix: "/api/v1/plugins/test",
			Endpoints: []PluginEndpoint{
				{Method: "POST", Path: "/fail", Description: "Fail test"},
			},
		}})
	})
	mux.HandleFunc("/api/v1/plugins/test/fail", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{"code": "boom", "message": "something broke"},
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/test/actions/fail", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `hx-swap-oob`) {
		t.Error("error action should include OOB toast")
	}
	if !strings.Contains(body, `toast-error`) {
		t.Error("error action should include error toast class")
	}
	if !strings.Contains(body, `error-details`) {
		t.Error("error action should include expandable error details")
	}
}

// ---------------------------------------------------------------------------
// Fragment endpoint tests — data loads via /fragments/* endpoints
// ---------------------------------------------------------------------------

func TestDashboardFragment_WithMockAPI(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/dashboard", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"test-node", "Debian 12", "arm", "2d 5h 10m"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard fragment should contain %q", want)
		}
	}
}

func TestDashboardFragment_WithAPIError(t *testing.T) {
	h := newTestHandler(t, "http://localhost:1", "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/dashboard", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to load system info") {
		t.Fatal("fragment should show error when API unreachable")
	}
}

func TestUpdateFragment_WithMockAPI(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"5", "2", "Security Update", "full", "completed",
		"openssl", "3.0.1", "3.0.2",
		"curl", "7.88.0", "7.88.1",
		"Duration: 2m 15s", "Packages: 3",
		"View log output",
		"Updating openssl",
		"Run a full system update?",
		"Run security-only update?",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("update fragment should contain %q", want)
		}
	}
}

func TestUpdateFragment_WithAPIError(t *testing.T) {
	h := newTestHandler(t, "http://localhost:1", "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to load pending updates") {
		t.Fatal("fragment should show error when API unreachable")
	}
}

func TestUpdateFragment_EmptyPendingHidesTable(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/plugins/update/status":
			json.NewEncoder(w).Encode([]PendingUpdate{})
		case "/api/v1/plugins/update/logs":
			json.NewEncoder(w).Encode(RunStatus{Type: "full", Status: "completed"})
		case "/api/v1/plugins/update/config":
			json.NewEncoder(w).Encode(UpdateConfig{SecurityAvailable: boolPtr(true)})
		case "/api/v1/plugins":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v1/node":
			json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "<th>Package</th>") {
		t.Error("package table should not render when pending list is empty")
	}
	if strings.Contains(body, "View log output") {
		t.Error("log viewer should not render when log is empty")
	}
}

func TestUpdateFragment_SecurityShownWhenAvailable(t *testing.T) {
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
		case "/api/v1/plugins":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v1/node":
			json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/update", nil)
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

func TestUpdateFragment_SecurityHiddenWhenUnavailable(t *testing.T) {
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
		case "/api/v1/plugins":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v1/node":
			json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/update", nil)
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
	if strings.Contains(w.Body.String(), "View log output") {
		t.Fatal("log viewer should be absent when RunStatus.Log is empty")
	}
}

func TestUpdateFragment_SecurityHiddenWhenNil(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/plugins/update/status":
			json.NewEncoder(w).Encode([]PendingUpdate{
				{Package: "vim", CurrentVersion: "9.0.1", NewVersion: "9.0.2"},
			})
		case "/api/v1/plugins/update/logs":
			json.NewEncoder(w).Encode(RunStatus{})
		case "/api/v1/plugins/update/config":
			json.NewEncoder(w).Encode(UpdateConfig{})
		case "/api/v1/plugins":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v1/node":
			json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/update", nil)
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

func TestUpdateFragment_PartialAPIFailure(t *testing.T) {
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
		case "/api/v1/plugins":
			json.NewEncoder(w).Encode([]map[string]any{})
		case "/api/v1/node":
			json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/update", nil)
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

func TestUpdateFragment_ShowsEditForm(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/update", nil)
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

func TestNetworkFragment_WithMockAPI(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/network", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"eth0", "192.168.1.10/24", "Online", "1.1.1.1"} {
		if !strings.Contains(body, want) {
			t.Errorf("network fragment should contain %q", want)
		}
	}
}

func TestNetworkFragment_WithAPIError(t *testing.T) {
	h := newTestHandler(t, "http://localhost:1", "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/network", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to load network status") {
		t.Fatal("fragment should show error when API unreachable")
	}
}

func TestPluginFragment_RendersForKnownPlugin(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodGet, "/fragments/firewall", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Firewall management") {
		t.Error("fragment should show plugin description")
	}
	if !strings.Contains(body, "Active firewall rules") {
		t.Error("fragment should show endpoint description")
	}
	if !strings.Contains(body, "Reload firewall rules") {
		t.Error("fragment should show POST action button")
	}
	if strings.Contains(body, "/api/v1/plugins/firewall/reload") {
		t.Error("action button should NOT use direct API path")
	}
	if !strings.Contains(body, "/firewall/actions/reload") {
		t.Error("action button should use proxied web path")
	}
	if !strings.Contains(body, `hx-confirm="Execute`) {
		t.Error("generic POST actions should have hx-confirm for safety")
	}
	if !strings.Contains(body, "allow 22/tcp") {
		t.Error("fragment should render fetched endpoint data")
	}
}

func TestPluginFragment_EndpointError(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodGet, "/fragments/metrics", nil)
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

func TestPluginFragment_SkipsEmptyPathPOST(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodGet, "/fragments/firewall", nil)
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

func TestPluginFragment_SkipsTraversalPOSTPath(t *testing.T) {
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

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/firewall", nil)
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

func TestPluginFragment_UnknownPlugin404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{Name: "firewall", Version: "1.0.0", RoutePrefix: "/api/v1/plugins/firewall"},
		})
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/fragments/nonexistent", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown plugin fragment, got %d", w.Code)
	}
}

// TestPluginPage_CacheFallbackOnAPIError verifies that plugin page requests
// use cached plugins when the API is down, instead of returning 502.
func TestPluginPage_CacheFallbackOnAPIError(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			json.NewEncoder(w).Encode([]PluginInfo{
				{Name: "firewall", Version: "1.0.0", RoutePrefix: "/api/v1/plugins/firewall"},
			})
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")

	// First request: populates plugin cache.
	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w.Code)
	}

	// Expire cache so fetchPlugins actually calls the API again.
	h.cache.mu.Lock()
	h.cache.fetchedAt = h.cache.fetchedAt.Add(-2 * h.cache.ttl)
	h.cache.mu.Unlock()

	// Second request: API returns 500, should fall back to cached plugin.
	req = httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("cache fallback: expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestPluginPage_NoDuplicateFetchPlugins verifies that handleGenericPlugin
// pre-populates the plugin list so withPlugins does not call fetchPlugins again.
func TestPluginPage_NoDuplicateFetchPlugins(t *testing.T) {
	fetchCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		fetchCount++
		json.NewEncoder(w).Encode([]PluginInfo{
			{Name: "firewall", Version: "1.0.0", RoutePrefix: "/api/v1/plugins/firewall"},
		})
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")

	// Ensure cache is empty so every fetchPlugins call hits the API.
	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	// lookupPlugin calls fetchPlugins once; withPlugins should reuse pre-populated
	// Plugins and NOT call fetchPlugins again, so total should be 1.
	if fetchCount != 1 {
		t.Errorf("expected 1 fetchPlugins call, got %d (double-fetch not eliminated)", fetchCount)
	}
}

// TestPluginPage_CacheFallback_UnknownPlugin404 verifies that when the API is
// down and the requested plugin is NOT in the stale cache, we get 404 (not 502).
func TestPluginPage_CacheFallback_UnknownPlugin404(t *testing.T) {
	calls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			json.NewEncoder(w).Encode([]PluginInfo{
				{Name: "firewall", Version: "1.0.0", RoutePrefix: "/api/v1/plugins/firewall"},
			})
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")

	// Prime cache with "firewall".
	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("prime: expected 200, got %d", w.Code)
	}

	// Expire plugin cache.
	h.cache.mu.Lock()
	h.cache.fetchedAt = h.cache.fetchedAt.Add(-2 * h.cache.ttl)
	h.cache.mu.Unlock()

	// Request "backup" (not in stale cache) while API is down → should 404.
	req = httptest.NewRequest(http.MethodGet, "/backup", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown plugin with stale cache, got %d", w.Code)
	}
}

// TestPluginPage_CacheFallback_SkipsNodeFetch verifies that when the plugin
// registry fetch fails and cache fallback is used, the sidebar node-info
// fetch is skipped (avoids compounding a down API with more failing calls).
func TestPluginPage_CacheFallback_SkipsNodeFetch(t *testing.T) {
	pluginCalls := 0
	nodeCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		pluginCalls++
		if pluginCalls == 1 {
			json.NewEncoder(w).Encode([]PluginInfo{
				{Name: "firewall", Version: "1.0.0", RoutePrefix: "/api/v1/plugins/firewall"},
			})
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		nodeCalls++
		json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
	})

	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")

	// Prime: healthy request populates both plugin and node caches.
	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("prime: expected 200, got %d", w.Code)
	}
	primeNodeCalls := nodeCalls

	// Expire both caches so next request must re-fetch.
	h.cache.mu.Lock()
	h.cache.fetchedAt = h.cache.fetchedAt.Add(-2 * h.cache.ttl)
	h.cache.mu.Unlock()
	h.nodes.mu.Lock()
	h.nodes.fetchedAt = h.nodes.fetchedAt.Add(-2 * h.nodes.ttl)
	h.nodes.mu.Unlock()

	// Second request: plugin API down, should use cache fallback and
	// NOT attempt the node-info fetch.
	req = httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("cache fallback: expected 200, got %d", w.Code)
	}

	if nodeCalls != primeNodeCalls {
		t.Errorf("expected no additional /api/v1/node calls during cache fallback, got %d extra",
			nodeCalls-primeNodeCalls)
	}
}
