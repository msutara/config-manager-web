package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestHandler(t *testing.T, apiURL, token string) *Handler {
	t.Helper()
	h := NewHandler(apiURL, token).(*Handler)
	return h
}

// ---------- Auth tests ----------

func TestLoginPage_Renders(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "secret")
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Access Token") {
		t.Fatal("login page should contain token input")
	}
}

func TestLoginPage_RedirectsWhenNoAuth(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "")
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/" {
		t.Fatalf("expected redirect to /, got %s", w.Header().Get("Location"))
	}
}

func TestAuthLogin_ValidToken(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "my-token")
	form := url.Values{"token": {"my-token"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/" {
		t.Fatalf("expected redirect to /, got %s", w.Header().Get("Location"))
	}

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
			if c.Value != "my-token" {
				t.Fatalf("cookie value = %q, want %q", c.Value, "my-token")
			}
			if !c.HttpOnly {
				t.Fatal("cookie should be httpOnly")
			}
			if c.MaxAge != 86400 {
				t.Fatalf("cookie MaxAge = %d, want 86400", c.MaxAge)
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("cookie SameSite = %d, want Strict", c.SameSite)
			}
		}
	}
	if !found {
		t.Fatal("session cookie not set")
	}
}

func TestAuthLogin_InvalidToken(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "my-token")
	form := url.Values{"token": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "error=invalid") {
		t.Fatal("expected redirect to login with error")
	}
}

func TestAuthLogin_EmptyToken(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "my-token")
	form := url.Values{"token": {""}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Location"), "error=invalid") {
		t.Fatal("expected redirect to login with error")
	}
}

func TestAuthLogout_ClearsCookie(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "my-token")
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "my-token"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}

	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge == -1 {
			if c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("logout cookie SameSite = %d, want Strict", c.SameSite)
			}
			return
		}
	}
	t.Fatal("session cookie should be cleared with MaxAge=-1")
}

// ---------- Session middleware tests ----------

func TestRequireSession_RedirectsWithoutCookie(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "secret")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/login" {
		t.Fatalf("expected redirect to /login, got %s", w.Header().Get("Location"))
	}
}

func TestRequireSession_AllowsValidCookie(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "secret")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "secret"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Dashboard will fail to reach API but should return 200 with error message
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRequireSession_RejectsInvalidCookie(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "secret")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "wrong"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", w.Code)
	}
}

func TestRequireSession_BypassedWhenNoAuth(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ---------- Static files ----------

func TestStaticFiles_NoAuthRequired(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "secret")
	req := httptest.NewRequest(http.MethodGet, "/static/style.css", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("expected CSS content-type, got %s", w.Header().Get("Content-Type"))
	}
}

func TestStaticFiles_HtmxServed(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "secret")
	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ---------- Page rendering with mock API ----------

func TestDashboard_RendersWithAPIError(t *testing.T) {
	h := newTestHandler(t, "http://localhost:1", "secret")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "secret"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to load system info") {
		t.Fatal("should show error when API unreachable")
	}
}

func TestUpdatePage_RendersWithAPIError(t *testing.T) {
	h := newTestHandler(t, "http://localhost:1", "secret")
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "secret"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to load pending updates") {
		t.Fatal("should show error when API unreachable")
	}
}

func TestNetworkPage_RendersWithAPIError(t *testing.T) {
	h := newTestHandler(t, "http://localhost:1", "secret")
	req := httptest.NewRequest(http.MethodGet, "/network", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "secret"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Failed to load network status") {
		t.Fatal("should show error when API unreachable")
	}
}

// ---------- formatUptime tests ----------

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		seconds int
		want    string
	}{
		{0, "just started"},
		{-1, "just started"},
		{30, "0m"},
		{60, "1m"},
		{90, "1m"},
		{3600, "1h 0m"},
		{3661, "1h 1m"},
		{7200, "2h 0m"},
		{86400, "1d 0h 0m"},
		{90061, "1d 1h 1m"},
		{191400, "2d 5h 10m"},
		{604800, "7d 0h 0m"},
	}
	for _, tt := range tests {
		got := formatUptime(tt.seconds)
		if got != tt.want {
			t.Errorf("formatUptime(%d) = %q, want %q", tt.seconds, got, tt.want)
		}
	}
}

// ---------- Stale cache fallback tests ----------

func TestSidebarUsesStaleCache_WhenAPIDown(t *testing.T) {
	// Start a real API server that serves plugins.
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/plugins":
			json.NewEncoder(w).Encode([]PluginInfo{
				{Name: "firewall", Version: "0.1.0", Description: "FW", RoutePrefix: "/api/v1/plugins/firewall"},
			})
		case "/api/v1/node":
			json.NewEncoder(w).Encode(NodeInfo{Hostname: "test"})
		}
	}))
	t.Cleanup(api.Close)

	h := NewHandler(api.URL, "").(*Handler)

	// Prime the cache with a successful request.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on first request, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `href="/firewall"`) {
		t.Fatal("first request should show firewall link")
	}

	// Shut down the API and force cache expiry deterministically.
	api.Close()
	h.cache.mu.Lock()
	h.cache.fetchedAt = time.Now().Add(-h.cache.ttl - time.Second)
	h.cache.mu.Unlock()

	// Verify cache is expired via get().
	if _, ok := h.cache.get(); ok {
		t.Fatal("cache should be expired")
	}

	// Request again — API is down, cache is expired. Sidebar should still
	// show stale data via getAny().
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with stale cache, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `href="/firewall"`) {
		t.Error("sidebar should show stale cached plugins when API is down")
	}
}

// ---------- Sidebar node info tests ----------

func TestSidebar_ShowsHostnameAndUptime(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/update", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, body)
	}
	for _, want := range []string{"test-node", "conn-dot", "conn-ok", "up 2d"} {
		if !strings.Contains(body, want) {
			t.Errorf("sidebar should contain %q", want)
		}
	}
}

func TestSidebar_NoCrashWhenAPIDown(t *testing.T) {
	// Point at a closed server — API unreachable.
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	h := newTestHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 even when API is down, got %d", w.Code)
	}
	// Sidebar info section should be absent (graceful degradation).
	if strings.Contains(w.Body.String(), "sidebar-host") {
		t.Error("sidebar should not show host info when API is unreachable")
	}
}

// ---------- Thundering herd prevention tests ----------

func TestFetchPlugins_DoubleCheck(t *testing.T) {
	var apiCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/plugins" {
			apiCalls.Add(1)
			// Small delay to let goroutines pile up at the lock.
			time.Sleep(10 * time.Millisecond)
			json.NewEncoder(w).Encode([]PluginInfo{
				{Name: "test", Version: "0.1.0", RoutePrefix: "/api/v1/plugins/test"},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer api.Close()

	h := NewHandler(api.URL, "").(*Handler)
	// Use a long TTL so the cache stays valid after the first fetch.
	// With a tiny TTL the cache could expire between the first goroutine's
	// fetch and the remaining goroutines' double-check, causing multiple
	// API calls and flaky failures.
	h.cache.ttl = 5 * time.Second

	const goroutines = 20
	var wg sync.WaitGroup
	// Barrier: all goroutines start at roughly the same time.
	barrier := make(chan struct{})

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if _, err := h.fetchPlugins(req); err != nil {
				t.Errorf("fetchPlugins: %v", err)
			}
		}()
	}

	// Release all goroutines simultaneously.
	close(barrier)
	wg.Wait()

	calls := apiCalls.Load()
	if calls != 1 {
		t.Errorf("expected exactly 1 API call (double-check mutex), got %d", calls)
	}
}
