// Package web provides a browser-based dashboard for Config Manager.
// It uses htmx + Go html/template for server-rendered pages with dynamic
// updates, served alongside the JSON API on the same port.
package web

import (
	"bytes"
	"crypto/subtle"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Handler serves the web UI and proxies actions to the CM JSON API.
type Handler struct {
	router    chi.Router
	apiURL    string
	authToken string
	templates map[string]*template.Template
	client    *apiClient
}

// NewHandler creates a web UI handler that renders pages and proxies actions
// to the CM JSON API at apiURL. When authToken is non-empty, a login page
// gates access via cookie-based sessions.
func NewHandler(apiURL, authToken string) http.Handler {
	h := &Handler{
		apiURL:    apiURL,
		authToken: authToken,
		client:    newAPIClient(apiURL, authToken),
	}

	funcMap := template.FuncMap{
		"derefBool": func(b *bool) bool {
			if b == nil {
				return false
			}
			return *b
		},
	}

	// Parse each page template with its own copy of the layout to avoid
	// "content" block name collisions between pages.
	layoutBytes, _ := fs.ReadFile(templateFS, "templates/layout.html")
	h.templates = make(map[string]*template.Template)
	for _, page := range []string{"dashboard.html", "update.html", "network.html"} {
		t := template.Must(template.New("").Funcs(funcMap).Parse(string(layoutBytes)))
		pageBytes, _ := fs.ReadFile(templateFS, "templates/"+page)
		template.Must(t.Parse(string(pageBytes)))
		h.templates[page] = t
	}
	// Login is standalone (no layout).
	loginBytes, _ := fs.ReadFile(templateFS, "templates/login.html")
	h.templates["login.html"] = template.Must(
		template.New("").Funcs(funcMap).Parse(string(loginBytes)))

	h.router = chi.NewRouter()

	// Static assets — no auth required.
	staticSub, _ := fs.Sub(staticFS, "static")
	h.router.Handle("/static/*", http.StripPrefix("/static/",
		http.FileServer(http.FS(staticSub))))

	// Login page — no auth required.
	h.router.Get("/login", h.handleLogin)
	h.router.Post("/auth/login", h.handleAuthLogin)

	// All other routes require valid session cookie.
	h.router.Group(func(r chi.Router) {
		r.Use(h.requireSession)
		r.Post("/auth/logout", h.handleAuthLogout)
		r.Get("/", h.handleDashboard)
		r.Get("/update", h.handleUpdate)
		r.Post("/update/run", h.handleUpdateRun)
		r.Get("/network", h.handleNetwork)
	})

	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

// validToken checks whether the provided token matches the configured auth
// token using constant-time comparison.
func (h *Handler) validToken(token string) bool {
	if h.authToken == "" {
		return true // auth disabled
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(h.authToken)) == 1
}

// render executes a named template into a buffer first (to avoid garbled
// output on mid-render errors), then writes the result.
func (h *Handler) render(w http.ResponseWriter, name string, data any) {
	t, ok := h.templates[name]
	if !ok {
		slog.Error("template not found", "template", name)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	execName := "page"
	if name == "login.html" {
		execName = "login.html"
	}

	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, execName, data); err != nil {
		slog.Error("template render error", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}
