package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockAPI creates a test server that simulates the CM JSON API.
func mockAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{
			Hostname: "test-node",
			OS:       "Debian 12",
			Arch:     "arm",
			Uptime:   "2d 5h 30m",
		})
	})

	mux.HandleFunc("/api/v1/plugins/update/status", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(UpdateStatus{
			Running:       false,
			LastRun:       "2026-02-27T10:00:00Z",
			LastResult:    "success",
			PendingCount:  5,
			SecurityCount: 2,
		})
	})

	mux.HandleFunc("/api/v1/plugins/update/config", func(w http.ResponseWriter, _ *http.Request) {
		avail := true
		json.NewEncoder(w).Encode(UpdateConfig{
			SecurityAvailable:  &avail,
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
			{Name: "eth0", Type: "ether", State: "routable", Address: "192.168.1.10/24", Gateway: "192.168.1.1"},
			{Name: "wlan0", Type: "wlan", State: "off"},
		})
	})

	mux.HandleFunc("/api/v1/plugins/network/status", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NetworkStatus{
			Online:     true,
			DNSWorking: true,
			PublicIP:   "1.2.3.4",
		})
	})

	mux.HandleFunc("/api/v1/plugins/network/dns", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(DNSConfig{
			Servers: []string{"1.1.1.1", "8.8.8.8"},
			Search:  []string{"local"},
		})
	})

	return httptest.NewServer(mux)
}

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
	for _, want := range []string{"test-node", "Debian 12", "arm", "2d 5h 30m"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard should contain %q", want)
		}
	}
}

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
	for _, want := range []string{"Idle", "5", "2", "Security Update"} {
		if !strings.Contains(body, want) {
			t.Errorf("update page should contain %q", want)
		}
	}
}

func TestUpdatePage_SecurityHiddenWhenUnavailable(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/plugins/update/status":
			json.NewEncoder(w).Encode(UpdateStatus{PendingCount: 3})
		case "/api/v1/plugins/update/config":
			unavail := false
			json.NewEncoder(w).Encode(UpdateConfig{SecurityAvailable: &unavail})
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
	if !strings.Contains(w.Body.String(), "started successfully") {
		t.Fatal("should show success message")
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
	err := c.post(context.Background(), "/api/v1/plugins/update/run", nil)
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
	c.get(context.Background(), "/test", nil)

	if gotAuth != "Bearer test-token" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer test-token")
	}
}

// ---------- Additional coverage tests ----------

func TestUpdateRun_SecurityType(t *testing.T) {
	var gotPath string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
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
	if gotPath != "/api/v1/plugins/update/run?type=security" {
		t.Fatalf("API path = %q, want security path", gotPath)
	}
	if !strings.Contains(w.Body.String(), "security") {
		t.Fatal("response should mention security")
	}
}

func TestUpdateRun_DefaultType(t *testing.T) {
	var gotPath string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	// POST with empty body - no type field.
	req := httptest.NewRequest(http.MethodPost, "/update/run", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gotPath != "/api/v1/plugins/update/run" {
		t.Fatalf("API path = %q, want full update path", gotPath)
	}
	if !strings.Contains(w.Body.String(), "full") {
		t.Fatal("response should mention full")
	}
}

func TestUpdateRun_XSSSanitized(t *testing.T) {
	// The handler validates against allowlist, so injected type is replaced with "full".
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
	if !strings.Contains(w.Body.String(), "full") {
		t.Fatal("invalid type should default to full")
	}
}

func TestAPIClient_PostErrorStatus(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"broken"}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.post(context.Background(), "/fail", nil)
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
	err := c.post(context.Background(), "/ok", nil)
	if err != nil {
		t.Fatalf("204 should not be an error: %v", err)
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
