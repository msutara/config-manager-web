package web

import (
	"log/slog"
	"net/http"
)

const sessionCookieName = "cm_session"

// requireSession is middleware that validates the session cookie.
// When auth is disabled (empty token), all requests pass through.
// For htmx requests (HX-Request header), returns 401 with HX-Redirect
// instead of 303 redirect to avoid embedding the login page in fragments.
func (h *Handler) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.authToken == "" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || !h.validToken(cookie.Value) {
			slog.Debug("web: invalid or missing session cookie", "path", r.URL.Path)
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/login")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleLogin renders the login page.
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	// If auth is disabled, redirect straight to dashboard.
	if h.authToken == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	data := map[string]any{
		"Error": sanitizeForDisplay(r.URL.Query().Get("error")),
	}
	h.render(w, "login.html", data)
}

// handleAuthLogin validates the submitted token and sets a session cookie.
func (h *Handler) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if err := parseFormLimited(w, r); err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	token := r.FormValue("token")
	if token == "" || !h.validToken(token) {
		slog.Warn("web: failed login attempt", "remote", r.RemoteAddr)
		http.Redirect(w, r, "/login?error=invalid", http.StatusSeeOther)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	})

	slog.Info("web: successful login", "remote", r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleAuthLogout clears the session cookie.
func (h *Handler) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
