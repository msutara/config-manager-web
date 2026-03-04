// Package web provides a browser-based dashboard for Config Manager.
// It uses htmx + Go html/template for server-rendered pages with dynamic
// updates, served alongside the JSON API on the same port.
package web

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
)

// pluginCache holds a TTL-based cache of the plugin registry to avoid
// repeated API calls on every page load.
type pluginCache struct {
	mu        sync.RWMutex
	plugins   []PluginInfo
	fetchedAt time.Time
	ttl       time.Duration
	refreshMu sync.Mutex // serializes API fetches on cache miss
}

func (c *pluginCache) get() ([]PluginInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if time.Since(c.fetchedAt) < c.ttl && c.plugins != nil {
		return c.plugins, true
	}
	return nil, false
}

func (c *pluginCache) set(plugins []PluginInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.plugins = plugins
	c.fetchedAt = time.Now()
}

// getAny returns cached plugins regardless of TTL expiry. Used as fallback
// when the API is unreachable.
func (c *pluginCache) getAny() ([]PluginInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.plugins != nil {
		return c.plugins, true
	}
	return nil, false
}

// Handler serves the web UI and proxies actions to the CM JSON API.
type Handler struct {
	router    chi.Router
	apiURL    string
	authToken string
	templates map[string]*template.Template
	client    *apiClient
	cache     pluginCache
}

// formatUptime converts seconds to a human-readable "Xd Xh Xm" string.
func formatUptime(seconds int) string {
	if seconds <= 0 {
		return "just started"
	}
	d := seconds / 86400
	h := (seconds % 86400) / 3600
	m := (seconds % 3600) / 60
	if d > 0 {
		return fmt.Sprintf("%dd %dh %dm", d, h, m)
	}
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// titleCase converts a hyphen-separated plugin name to Title Case with spaces.
// Uses rune-aware uppercasing to handle multi-byte UTF-8 safely.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	parts := strings.Split(s, "-")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		r, size := utf8.DecodeRuneInString(p)
		result = append(result, string(unicode.ToUpper(r))+p[size:])
	}
	return strings.Join(result, " ")
}

// NewHandler creates a web UI handler that renders pages and proxies actions
// to the CM JSON API at apiURL. When authToken is non-empty, a login page
// gates access via cookie-based sessions.
func NewHandler(apiURL, authToken string) http.Handler {
	h := &Handler{
		apiURL:    apiURL,
		authToken: authToken,
		client:    newAPIClient(apiURL, authToken),
		cache:     pluginCache{ttl: 30 * time.Second},
	}

	funcMap := template.FuncMap{
		"formatUptime": formatUptime,
		"title":        titleCase,
		"derefBool": func(b *bool) bool {
			if b == nil {
				return false
			}
			return *b
		},
	}

	mustRead := func(name string) []byte {
		b, err := fs.ReadFile(templateFS, "templates/"+name)
		if err != nil {
			panic("read " + name + ": " + err.Error())
		}
		return b
	}

	// Parse each page template with its own copy of the layout to avoid
	// "content" block name collisions between pages.
	layoutBytes := mustRead("layout.html")
	h.templates = make(map[string]*template.Template)
	for _, page := range []string{"dashboard.html", "update.html", "network.html", "plugin.html"} {
		t := template.Must(template.New("").Funcs(funcMap).Parse(string(layoutBytes)))
		template.Must(t.Parse(string(mustRead(page))))
		h.templates[page] = t
	}
	// Login is standalone (no layout).
	h.templates["login.html"] = template.Must(
		template.New("").Funcs(funcMap).Parse(string(mustRead("login.html"))))

	h.router = chi.NewRouter()

	// Static assets — no auth required.
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("fs.Sub static: " + err.Error())
	}
	h.router.Handle("/static/*", http.StripPrefix("/static/",
		http.FileServer(http.FS(staticSub))))

	// Login page — no auth required.
	h.router.Get("/login", h.handleLogin)
	h.router.Post("/auth/login", h.handleAuthLogin)

	// All other routes require valid session cookie.
	h.router.Group(func(r chi.Router) {
		r.Use(h.requireSession)
		r.Post("/auth/logout", h.handleAuthLogout)

		// Generic plugin routes — regex constrains to valid plugin names.
		// Chi radix trie ensures literal routes (/update, /network) always
		// win over these param routes.
		r.Get("/{plugin:[a-z][a-z0-9-]*}", h.handleGenericPlugin)
		r.Post("/{plugin:[a-z][a-z0-9-]*}/actions/*", h.handleGenericAction)

		// Dashboard.
		r.Get("/", h.handleDashboard)

		// Update plugin (custom handlers for richer UX).
		r.Get("/update", h.handleUpdate)
		r.Post("/update/run", h.handleUpdateRun)
		r.Post("/update/settings", h.handleUpdateSettings)

		// Network plugin (custom handler for richer UX).
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
	_, _ = w.Write(buf.Bytes()) //nolint:errcheck // HTTP response write
}

// fetchPlugins retrieves the plugin list from the core API, using a
// TTL-based cache to avoid repeated calls on every page load. A refresh
// mutex prevents thundering-herd when multiple requests hit an expired
// cache simultaneously.
func (h *Handler) fetchPlugins(r *http.Request) ([]PluginInfo, error) {
	if cached, ok := h.cache.get(); ok {
		return cached, nil
	}

	// Serialize refreshes to prevent thundering herd.
	h.cache.refreshMu.Lock()
	defer h.cache.refreshMu.Unlock()

	// Double-check after acquiring lock — another goroutine may have refreshed.
	if cached, ok := h.cache.get(); ok {
		return cached, nil
	}

	var plugins []PluginInfo
	if err := h.client.get(r.Context(), "/api/v1/plugins", &plugins); err != nil {
		return nil, err
	}
	// Validate route prefixes before caching — reject malicious entries.
	valid := plugins[:0]
	for _, p := range plugins {
		if err := validateRoutePrefix(p.RoutePrefix); err != nil {
			slog.Warn("web: dropping plugin with invalid RoutePrefix",
				"plugin", p.Name, "prefix", p.RoutePrefix, "error", err)
			continue
		}
		valid = append(valid, p)
	}
	plugins = valid
	h.cache.set(plugins)
	return plugins, nil
}

// withPlugins adds the Plugins list to a template data map with fallback to
// stale cached data when the API is unreachable. If both the API and cache
// (including expired entries) are empty, PluginsUnavailable is set so the
// template can show a message.
func (h *Handler) withPlugins(r *http.Request, data map[string]any) map[string]any {
	plugins, err := h.fetchPlugins(r)
	if err != nil {
		slog.Debug("web: sidebar plugin fetch failed, trying stale cache", "error", err)
		if cached, ok := h.cache.getAny(); ok {
			plugins = cached
		}
	}
	data["Plugins"] = plugins
	if err != nil && len(plugins) == 0 {
		data["PluginsUnavailable"] = true
	}
	return data
}
