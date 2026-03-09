package web

import (
	"encoding/json"
	"fmt"
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

func TestAuthLogin_OversizedBody(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "my-token")
	// Create a body larger than maxFormBytes (1 MB).
	bigBody := strings.Repeat("x", 2<<20)
	form := url.Values{"token": {bigBody}}
	req := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Oversized body must be rejected — redirect back to login (no 200 or cookie).
	if w.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect for oversized body, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName {
			t.Fatal("session cookie must not be set when body is oversized")
		}
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

func TestRequireSession_HXRedirectForHtmxRequests(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "secret")
	req := httptest.NewRequest(http.MethodGet, "/fragments/dashboard", nil)
	req.Header.Set("HX-Request", "true")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for htmx request without session, got %d", w.Code)
	}
	if loc := w.Header().Get("HX-Redirect"); loc != "/login" {
		t.Fatalf("expected HX-Redirect: /login, got %q", loc)
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
	// Page now shows skeleton; error message appears in the fragment.
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/dashboard"`) {
		t.Error("dashboard should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("dashboard should contain skeleton placeholders")
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
	// Page now shows skeleton; error message appears in the fragment.
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/update"`) {
		t.Error("update page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("update page should contain skeleton placeholders")
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
	// Page now shows skeleton; error message appears in the fragment.
	body := w.Body.String()
	if !strings.Contains(body, `hx-get="/fragments/network"`) {
		t.Error("network page should contain hx-get for lazy loading fragment")
	}
	if !strings.Contains(body, "skeleton") {
		t.Error("network page should contain skeleton placeholders")
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

// ---------- Security header tests ----------

func TestSecurityHeaders(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "secret")
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	checks := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
	}
	for header, want := range checks {
		got := w.Header().Get(header)
		if got != want {
			t.Errorf("header %s = %q, want %q", header, got, want)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header should be set")
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Error("CSP should contain default-src 'self'")
	}
}

func TestSecurityHeaders_OnAuthenticatedRoute(t *testing.T) {
	h := newTestHandler(t, "http://localhost:9999", "secret")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "secret"})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options should be DENY on authenticated routes")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options should be nosniff on authenticated routes")
	}
}

// ---------- Token masking tests ----------

func TestAPIClient_StringMasksToken(t *testing.T) {
	c := &apiClient{baseURL: "http://localhost", token: "secret123"}

	s := c.String()
	if strings.Contains(s, "secret123") {
		t.Error("String() should not contain the raw token")
	}
	if !strings.Contains(s, "REDACTED") {
		t.Error("String() should contain REDACTED")
	}
	if !strings.Contains(s, "http://localhost") {
		t.Error("String() should contain the baseURL")
	}
}

func TestAPIClient_GoStringMasksToken(t *testing.T) {
	c := &apiClient{baseURL: "http://localhost", token: "secret123"}

	s := fmt.Sprintf("%#v", c)
	if strings.Contains(s, "secret123") {
		t.Error("GoString() should not contain the raw token")
	}
	if !strings.Contains(s, "REDACTED") {
		t.Error("GoString() should contain REDACTED")
	}
}

// ---------- Body size limit tests ----------

func TestUpdateRun_BodySizeLimit(t *testing.T) {
	api := mockAPI(t)
	defer api.Close()

	h := newTestHandler(t, api.URL, "")
	// Create a body larger than maxFormBytes (1 MB).
	bigBody := strings.Repeat("x", 2<<20)
	form := url.Values{"type": {bigBody}}

	req := httptest.NewRequest(http.MethodPost, "/update/run",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "Request too large") && w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected body size error, got status %d body: %s", w.Code, body)
	}
}

// ---------- Sanitized transport error tests ----------

func TestSanitizeTransportError_StripsURL(t *testing.T) {
	origErr := &url.Error{
		Op:  "Get",
		URL: "http://internal-api:9090/secret/path",
		Err: fmt.Errorf("connection refused"),
	}
	sanitized := sanitizeTransportError(origErr)
	if sanitized == nil {
		t.Fatal("expected non-nil error")
	}
	if strings.Contains(sanitized.Error(), "internal-api") {
		t.Error("sanitized error should not contain the internal URL")
	}
	if strings.Contains(sanitized.Error(), "/secret/path") {
		t.Error("sanitized error should not contain the URL path")
	}
	if !strings.Contains(sanitized.Error(), "connection refused") {
		t.Error("sanitized error should contain the underlying cause")
	}
}

func TestSanitizeTransportError_NilPassthrough(t *testing.T) {
	if sanitizeTransportError(nil) != nil {
		t.Error("nil input should return nil")
	}
}

func TestSanitizeTransportError_NonURLError(t *testing.T) {
	err := fmt.Errorf("some generic error")
	got := sanitizeTransportError(err)
	if got != err {
		t.Error("non-url.Error should pass through unchanged")
	}
}
