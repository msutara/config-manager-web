package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
