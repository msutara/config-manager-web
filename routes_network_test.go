package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------- API client: putConfirm, deleteConfirm, postConfirm ----------

func TestAPIClient_PutConfirmSuccess(t *testing.T) {
	var gotConfirm, gotCT string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConfirm = r.Header.Get("X-Confirm")
		gotCT = r.Header.Get("Content-Type")
		json.NewEncoder(w).Encode(map[string]string{"result": "applied"})
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	body := strings.NewReader(`{"address":"10.0.0.1/24"}`)
	var dst map[string]string
	if err := c.putConfirm(context.Background(), "/test", body, &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotConfirm != "true" {
		t.Fatalf("X-Confirm = %q, want %q", gotConfirm, "true")
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotCT)
	}
	if dst["result"] != "applied" {
		t.Fatalf("result = %q, want %q", dst["result"], "applied")
	}
}

func TestAPIClient_PutConfirm204(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.putConfirm(context.Background(), "/ok", nil, nil)
	if err != nil {
		t.Fatalf("204 should not be an error: %v", err)
	}
}

func TestAPIClient_PutConfirmErrorStatus(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"message":"bad payload"}}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.putConfirm(context.Background(), "/fail", nil, nil)
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if !strings.Contains(err.Error(), "bad payload") {
		t.Fatalf("error should contain 'bad payload': %v", err)
	}
}

func TestAPIClient_PutConfirmSendsAuthToken(t *testing.T) {
	var gotAuth, gotConfirm string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotConfirm = r.Header.Get("X-Confirm")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "tok")
	_ = c.putConfirm(context.Background(), "/test", nil, nil)
	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer tok")
	}
	if gotConfirm != "true" {
		t.Fatalf("X-Confirm = %q, want %q", gotConfirm, "true")
	}
}

func TestAPIClient_DeleteConfirmSuccess(t *testing.T) {
	var gotConfirm, gotMethod string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotConfirm = r.Header.Get("X-Confirm")
		json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	var dst map[string]string
	if err := c.deleteConfirm(context.Background(), "/test", &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method = %q, want DELETE", gotMethod)
	}
	if gotConfirm != "true" {
		t.Fatalf("X-Confirm = %q, want %q", gotConfirm, "true")
	}
	if dst["status"] != "deleted" {
		t.Fatalf("status = %q, want %q", dst["status"], "deleted")
	}
}

func TestAPIClient_DeleteConfirmErrorStatus(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":{"message":"server error"}}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.deleteConfirm(context.Background(), "/fail", nil)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "server error") {
		t.Fatalf("error should contain 'server error': %v", err)
	}
}

func TestAPIClient_DeleteConfirmSendsAuthToken(t *testing.T) {
	var gotAuth, gotConfirm string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotConfirm = r.Header.Get("X-Confirm")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "tok")
	_ = c.deleteConfirm(context.Background(), "/test", nil)
	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer tok")
	}
	if gotConfirm != "true" {
		t.Fatalf("X-Confirm = %q, want %q", gotConfirm, "true")
	}
}

func TestAPIClient_DeleteConfirm204(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.deleteConfirm(context.Background(), "/ok", nil)
	if err != nil {
		t.Fatalf("204 should not be an error: %v", err)
	}
}

func TestAPIClient_PostConfirmSuccess(t *testing.T) {
	var gotConfirm, gotMethod string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotConfirm = r.Header.Get("X-Confirm")
		json.NewEncoder(w).Encode(map[string]string{"status": "rolled_back"})
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	var dst map[string]string
	if err := c.postConfirm(context.Background(), "/rollback", &dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if gotConfirm != "true" {
		t.Fatalf("X-Confirm = %q, want %q", gotConfirm, "true")
	}
	if dst["status"] != "rolled_back" {
		t.Fatalf("status = %q, want %q", dst["status"], "rolled_back")
	}
}

func TestAPIClient_PostConfirm202Accepted(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	var dst map[string]string
	if err := c.postConfirm(context.Background(), "/test", &dst); err != nil {
		t.Fatalf("202 should not be an error: %v", err)
	}
	if dst["status"] != "accepted" {
		t.Fatalf("status = %q, want %q", dst["status"], "accepted")
	}
}

func TestAPIClient_PostConfirm204(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.postConfirm(context.Background(), "/ok", nil)
	if err != nil {
		t.Fatalf("204 should not be an error: %v", err)
	}
}

func TestAPIClient_PostConfirmErrorStatus(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"message":"forbidden"}}`))
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "")
	err := c.postConfirm(context.Background(), "/fail", nil)
	if err == nil {
		t.Fatal("expected error for 403")
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("error should contain 'forbidden': %v", err)
	}
}

func TestAPIClient_PostConfirmSendsAuthToken(t *testing.T) {
	var gotAuth string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer api.Close()

	c := newAPIClient(api.URL, "secret-token")
	_ = c.postConfirm(context.Background(), "/test", nil)
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer secret-token")
	}
}

// ---------- Network write handler helpers ----------

// networkMockAPI creates a test server with the network write endpoints.
func networkMockAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Read endpoints needed for NewHandler initialization.
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{Name: "network", Version: "0.1.0", RoutePrefix: "/api/v1/plugins/network"},
		})
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{Hostname: "test-node"})
	})

	// Write endpoints.
	mux.HandleFunc("/api/v1/plugins/network/interfaces/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Confirm") != "true" {
			http.Error(w, `{"error":{"message":"X-Confirm header required"}}`, http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			var payload map[string]string
			json.Unmarshal(body, &payload)
			json.NewEncoder(w).Encode(NetworkWriteResult{
				Valid:   true,
				Message: "static IP applied for " + payload["address"],
			})
		case http.MethodDelete:
			json.NewEncoder(w).Encode(NetworkWriteResult{
				Valid:   true,
				Message: "static IP removed",
			})
		case http.MethodPost:
			// Rollback endpoint: /api/v1/plugins/network/interfaces/{name}/rollback
			json.NewEncoder(w).Encode(NetworkWriteResult{
				Valid:   true,
				Message: "rolled back",
			})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/api/v1/plugins/network/dns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Confirm") != "true" {
			http.Error(w, `{"error":{"message":"X-Confirm header required"}}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(NetworkWriteResult{Valid: true, Message: "DNS applied"})
	})
	mux.HandleFunc("/api/v1/plugins/network/dns/rollback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Confirm") != "true" {
			http.Error(w, `{"error":{"message":"X-Confirm header required"}}`, http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(NetworkWriteResult{Valid: true, Message: "DNS rolled back"})
	})

	return httptest.NewServer(mux)
}

// networkErrorAPI returns 500 for all network write endpoints.
func networkErrorAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{Hostname: "test-node"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":{"message":"backend down"}}`))
	})
	return httptest.NewServer(mux)
}

// ---------- handleNetworkSetStaticIP ----------

func TestNetworkSetStaticIP_ValidRequest(t *testing.T) {
	var capturedBody []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{
			{Name: "network", Version: "0.1.0", RoutePrefix: "/api/v1/plugins/network"},
		})
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{Hostname: "test-node"})
	})
	mux.HandleFunc("/api/v1/plugins/network/interfaces/", func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(NetworkWriteResult{
			Valid:   true,
			Message: "static IP applied",
		})
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=eth0&address=10.0.0.5%2F24&gateway=10.0.0.1&netmask=255.255.255.0"
	req := httptest.NewRequest(http.MethodPost, "/network/set-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	redir := w.Header().Get("HX-Redirect")
	if redir != "/network?flash=network-applied" {
		t.Errorf("HX-Redirect = %q, want /network?flash=network-applied", redir)
	}
	if body := w.Body.String(); body != "" {
		t.Errorf("expected empty body on redirect, got %q", body)
	}

	// CMW-02: Verify the outbound JSON payload includes the netmask field.
	if len(capturedBody) == 0 {
		t.Fatal("expected API to receive a request body, got nothing")
	}
	var payload map[string]string
	if err := json.Unmarshal(capturedBody, &payload); err != nil {
		t.Fatalf("failed to decode API request body: %v", err)
	}
	if payload["netmask"] != "255.255.255.0" {
		t.Errorf("netmask in API payload = %q, want %q", payload["netmask"], "255.255.255.0")
	}
}

func TestNetworkSetStaticIP_MissingName(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=&address=10.0.0.5%2F24"
	req := httptest.NewRequest(http.MethodPost, "/network/set-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Invalid interface name") {
		t.Errorf("expected 'Invalid interface name' error, got: %s", body)
	}
	if !strings.Contains(body, "toast") {
		t.Error("expected toast in response")
	}
}

func TestNetworkSetStaticIP_InvalidName(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=../evil&address=10.0.0.5%2F24"
	req := httptest.NewRequest(http.MethodPost, "/network/set-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Invalid interface name") {
		t.Errorf("expected 'Invalid interface name' error for traversal name, got: %s", body)
	}
}

func TestNetworkSetStaticIP_MissingAddress(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=eth0&address="
	req := httptest.NewRequest(http.MethodPost, "/network/set-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Address is required") {
		t.Errorf("expected 'Address is required' error, got: %s", body)
	}
}

func TestNetworkSetStaticIP_MissingNetmask(t *testing.T) {
	var apiCalled bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{Hostname: "test-node"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		apiCalled = true
		w.WriteHeader(http.StatusOK)
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=eth0&address=10.0.0.5%2F24&gateway=10.0.0.1"
	req := httptest.NewRequest(http.MethodPost, "/network/set-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Netmask is required") {
		t.Errorf("expected 'Netmask is required' error, got: %s", body)
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("expected OOB toast error in response")
	}
	if apiCalled {
		t.Error("API should not be called when netmask is missing")
	}
}

func TestNetworkSetStaticIP_APIError(t *testing.T) {
	api := networkErrorAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=eth0&address=10.0.0.5%2F24&netmask=255.255.255.0"
	req := httptest.NewRequest(http.MethodPost, "/network/set-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Failed to set static IP") {
		t.Errorf("expected API error message, got: %s", body)
	}
	if !strings.Contains(body, "backend down") {
		t.Errorf("expected error details in body, got: %s", body)
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("expected toast OOB swap in error response")
	}
}

func TestNetworkSetStaticIP_XSSEscaped(t *testing.T) {
	// Use a mock that includes a raw <script> tag in the error message.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/plugins", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode([]PluginInfo{})
	})
	mux.HandleFunc("/api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(NodeInfo{Hostname: "test-node"})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		// Manually write JSON with unescaped HTML to simulate a backend
		// that reflects unsanitized input in its error message.
		w.Write([]byte(`{"error":{"message":"bad value: <script>alert(1)</script>"}}`))
	})
	api := httptest.NewServer(mux)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=eth0&address=10.0.0.5%2F24&netmask=255.255.255.0"
	req := httptest.NewRequest(http.MethodPost, "/network/set-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "<script>") {
		t.Error("response should not contain raw <script> tag (XSS)")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("response should contain HTML-escaped script tag")
	}
}

// ---------- handleNetworkSetDNS ----------

func TestNetworkSetDNS_ValidRequest(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "nameservers=8.8.8.8%2C+1.1.1.1&search=home.lan%2C+local"
	req := httptest.NewRequest(http.MethodPost, "/network/set-dns", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	redir := w.Header().Get("HX-Redirect")
	if redir != "/network?flash=network-applied" {
		t.Errorf("HX-Redirect = %q, want /network?flash=network-applied", redir)
	}
}

func TestNetworkSetDNS_EmptyServers(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "nameservers="
	req := httptest.NewRequest(http.MethodPost, "/network/set-dns", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "At least one DNS server is required") {
		t.Errorf("expected DNS server required error, got: %s", body)
	}
}

func TestNetworkSetDNS_OnlyWhitespace(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "nameservers=+%2C+%2C+"
	req := httptest.NewRequest(http.MethodPost, "/network/set-dns", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "At least one DNS server is required") {
		t.Errorf("expected DNS server required error for whitespace-only, got: %s", body)
	}
}

func TestNetworkSetDNS_APIError(t *testing.T) {
	api := networkErrorAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "nameservers=8.8.8.8"
	req := httptest.NewRequest(http.MethodPost, "/network/set-dns", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Failed to set DNS") {
		t.Errorf("expected DNS error message, got: %s", body)
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("expected toast OOB swap in error response")
	}
}

// ---------- handleNetworkDeleteStaticIP ----------

func TestNetworkDeleteStaticIP_ValidRequest(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=eth0"
	req := httptest.NewRequest(http.MethodPost, "/network/delete-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	redir := w.Header().Get("HX-Redirect")
	if redir != "/network?flash=network-deleted" {
		t.Errorf("HX-Redirect = %q, want /network?flash=network-deleted", redir)
	}
}

func TestNetworkDeleteStaticIP_InvalidName(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=../bad"
	req := httptest.NewRequest(http.MethodPost, "/network/delete-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Invalid interface name") {
		t.Errorf("expected invalid name error, got: %s", body)
	}
}

func TestNetworkDeleteStaticIP_EmptyName(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name="
	req := httptest.NewRequest(http.MethodPost, "/network/delete-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Invalid interface name") {
		t.Errorf("expected invalid name error for empty, got: %s", body)
	}
}

func TestNetworkDeleteStaticIP_APIError(t *testing.T) {
	api := networkErrorAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=eth0"
	req := httptest.NewRequest(http.MethodPost, "/network/delete-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Failed to remove static IP") {
		t.Errorf("expected API error message, got: %s", body)
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("expected toast OOB swap in error response")
	}
}

// ---------- handleNetworkRollbackInterface ----------

func TestNetworkRollbackInterface_ValidRequest(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=eth0"
	req := httptest.NewRequest(http.MethodPost, "/network/rollback-interface", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	redir := w.Header().Get("HX-Redirect")
	if redir != "/network?flash=network-rollback" {
		t.Errorf("HX-Redirect = %q, want /network?flash=network-rollback", redir)
	}
}

func TestNetworkRollbackInterface_InvalidName(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name="
	req := httptest.NewRequest(http.MethodPost, "/network/rollback-interface", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Invalid interface name") {
		t.Errorf("expected invalid name error, got: %s", body)
	}
}

func TestNetworkRollbackInterface_APIError(t *testing.T) {
	api := networkErrorAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	form := "name=eth0"
	req := httptest.NewRequest(http.MethodPost, "/network/rollback-interface", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Failed to rollback") {
		t.Errorf("expected rollback error message, got: %s", body)
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("expected toast OOB swap in error response")
	}
}

// ---------- handleNetworkRollbackDNS ----------

func TestNetworkRollbackDNS_ValidRequest(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/network/rollback-dns", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	redir := w.Header().Get("HX-Redirect")
	if redir != "/network?flash=network-rollback" {
		t.Errorf("HX-Redirect = %q, want /network?flash=network-rollback", redir)
	}
}

func TestNetworkRollbackDNS_APIError(t *testing.T) {
	api := networkErrorAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodPost, "/network/rollback-dns", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Failed to rollback DNS") {
		t.Errorf("expected DNS rollback error message, got: %s", body)
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("expected toast OOB swap in error response")
	}
}

// ---------- validIfaceName regex ----------

func TestValidIfaceName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"simple", "eth0", true},
		{"with dot", "enp0s3.100", true},
		{"with hyphen", "wlan-0", true},
		{"with underscore", "br_lan", true},
		{"leading dot", ".hidden", false},
		{"leading hyphen", "-bad", false},
		{"empty", "", false},
		{"traversal", "../etc", false},
		{"space", "eth 0", false},
		{"slash", "eth0/1", false},
		{"null byte", "eth0\x00bad", false},
		{"unicode", "ethö", false},
		{"long name", strings.Repeat("a", 256), false}, // Linux IFNAMSIZ-1 = 15 chars max
		{"exactly 15 chars", strings.Repeat("a", 15), true},
		{"16 chars too long", strings.Repeat("a", 16), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validIfaceName.MatchString(tt.input)
			if got != tt.want {
				t.Errorf("validIfaceName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// ---------- Oversized body (MaxBytesReader DoS protection) ----------

func TestNetworkHandlers_OversizedBody(t *testing.T) {
	api := networkMockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	endpoints := []struct {
		name, path, form string
	}{
		{"SetStaticIP", "/network/set-static-ip", "name=eth0&address=10.0.0.1/24&pad="},
		{"SetDNS", "/network/set-dns", "nameservers=8.8.8.8&pad="},
		{"DeleteStaticIP", "/network/delete-static-ip", "name=eth0&pad="},
		{"RollbackInterface", "/network/rollback-interface", "name=eth0&pad="},
		{"RollbackDNS", "/network/rollback-dns", "pad="},
	}
	for _, ep := range endpoints {
		t.Run(ep.name, func(t *testing.T) {
			// Build a body that exceeds the 1 MB maxFormBytes limit.
			oversized := ep.form + strings.Repeat("x", 1<<20+1)
			req := httptest.NewRequest(http.MethodPost, ep.path, strings.NewReader(oversized))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			body := w.Body.String()
			if w.Code != http.StatusOK {
				t.Errorf("expected status 200 for htmx error rendering, got %d", w.Code)
			}
			if !strings.Contains(body, "Request too large") {
				t.Errorf("expected 'Request too large', got: %s", body)
			}
			if !strings.Contains(body, "hx-swap-oob") {
				t.Error("expected OOB toast in oversized-body response")
			}
		})
	}
}

// ---------- writeNetworkError generic error branch ----------

func TestWriteNetworkError_GenericError(t *testing.T) {
	// Point the handler at an unreachable API so the HTTP client returns a
	// generic (non-*APIError) error such as "connection refused".
	h := newTestHandler(t, "http://localhost:1", "")
	form := "name=eth0&address=10.0.0.1%2F24&netmask=255.255.255.0"
	req := httptest.NewRequest(http.MethodPost, "/network/set-static-ip", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Failed to set static IP") {
		t.Errorf("expected error title in response, got: %s", body)
	}
	if !strings.Contains(body, "hx-swap-oob") {
		t.Error("expected OOB toast in generic error response")
	}
	// Ensure the error detail block is present (the <pre> with error text).
	if !strings.Contains(body, "<pre>") {
		t.Error("expected error details in response")
	}
}

// ---------- Flash toast for network ----------

func TestParseFlashToast_NetworkValues(t *testing.T) {
	tests := []struct {
		flash   string
		wantMsg string
	}{
		{"network-applied", "Network configuration applied"},
		{"network-deleted", "Static IP removed, reverted to DHCP"},
		{"network-rollback", "Configuration rolled back"},
	}
	for _, tt := range tests {
		t.Run(tt.flash, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/network?flash="+tt.flash, nil)
			toast := parseFlashToast(req)
			if toast == nil {
				t.Fatal("expected toast, got nil")
			}
			if toast.Message != tt.wantMsg {
				t.Errorf("message = %q, want %q", toast.Message, tt.wantMsg)
			}
			if toast.Level != "success" {
				t.Errorf("level = %q, want success", toast.Level)
			}
		})
	}
}

// ---------- Network fragment shows write UI ----------

func TestNetworkFragment_ShowsWriteUI(t *testing.T) {
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
	for _, want := range []string{
		"set-static-ip",
		"set-dns",
		"delete-static-ip",
		"rollback-interface",
		"rollback-dns",
		"Apply Static IP",
		"Apply DNS Settings",
		"Rollback DNS",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("network fragment should contain %q", want)
		}
	}
}
