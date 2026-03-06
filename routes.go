package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
)

// ---------- Generic plugin handlers ----------

// maxConcurrentAPICalls limits goroutines spawned per request when fetching
// plugin endpoints concurrently.
const maxConcurrentAPICalls = 10

// EndpointData holds the result of fetching a single GET endpoint.
type EndpointData struct {
	Description string
	Data        string
	Error       string
}

// ActionInfo describes a POST endpoint for the generic plugin template.
type ActionInfo struct {
	Description string
	Path        string // relative path, e.g. "/run"
}

// cleanPluginPath builds a safe API path from a route prefix and endpoint path,
// rejecting path traversal (including percent-encoded sequences) and verifying
// the result stays under the expected prefix. routePrefix is trusted — it is
// set by the plugin registry (server-controlled, not user input).
func cleanPluginPath(routePrefix, epPath string) string {
	prefix := strings.TrimRight(routePrefix, "/")
	if prefix == "" {
		return ""
	}

	// Decode percent-encoding before validation to catch %2e%2e etc.
	decoded, err := url.PathUnescape(epPath)
	if err != nil {
		return ""
	}
	// Reject any remaining percent signs (double-encoding attempt).
	if strings.Contains(decoded, "%") {
		return ""
	}
	// Reject control characters (NUL, newlines, C1, etc.).
	for _, r := range decoded {
		if unicode.IsControl(r) {
			return ""
		}
	}
	if !strings.HasPrefix(decoded, "/") {
		decoded = "/" + decoded
	}

	// Canonicalize and verify no traversal escapes the prefix.
	full := path.Clean(prefix + decoded)
	if !strings.HasPrefix(full, prefix+"/") && full != prefix {
		return ""
	}
	return full
}

// validateRoutePrefix checks that a plugin's RoutePrefix is well-formed and
// safe. It rejects empty prefixes, missing leading slash, path traversal
// (including percent-encoded sequences), and control characters.
func validateRoutePrefix(prefix string) error {
	if prefix == "" {
		return fmt.Errorf("empty route prefix")
	}
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("route prefix must start with /")
	}
	// Decode percent-encoding to catch %2e%2e etc.
	decoded, err := url.PathUnescape(prefix)
	if err != nil {
		return fmt.Errorf("invalid percent-encoding in route prefix: %w", err)
	}
	// Reject remaining percent signs (double-encoding attempt).
	if strings.Contains(decoded, "%") {
		return fmt.Errorf("route prefix contains suspicious encoding")
	}
	if strings.Contains(decoded, "..") {
		return fmt.Errorf("route prefix contains path traversal")
	}
	for _, r := range decoded {
		if unicode.IsControl(r) {
			return fmt.Errorf("route prefix contains control character")
		}
	}
	// Reject dot-segments (e.g. /./foo or /foo/.) by canonicalizing and comparing.
	// Trim trailing slash before comparing since path.Clean removes it but
	// trailing slashes are valid in route prefixes.
	trimmed := strings.TrimRight(decoded, "/")
	if trimmed == "" {
		return fmt.Errorf("route prefix must not be bare \"/\" (use a meaningful namespace)")
	}
	if cleaned := path.Clean(trimmed); cleaned != trimmed {
		return fmt.Errorf("route prefix is not canonical (contains dot segments or redundant slashes)")
	}
	return nil
}

// lookupPlugin fetches the plugin registry and returns the named plugin, or
// nil if not found. The full plugin list is also returned for sidebar rendering.
// Returns an error only when the registry fetch itself fails.
func (h *Handler) lookupPlugin(r *http.Request, name string) (*PluginInfo, []PluginInfo, error) {
	plugins, err := h.fetchPlugins(r)
	if err != nil {
		return nil, nil, err
	}
	for i := range plugins {
		if plugins[i].Name == name {
			return &plugins[i], plugins, nil
		}
	}
	return nil, plugins, nil
}

// handleGenericPlugin renders a generic page for plugins without a custom
// template. It fetches all GET endpoints concurrently and lists POST
// endpoints as server-proxied action buttons.
func (h *Handler) handleGenericPlugin(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "plugin")

	found, plugins, err := h.lookupPlugin(r, name)
	if err != nil {
		slog.Error("web: plugin registry unavailable", "error", err)
		http.Error(w, "Plugin registry unavailable", http.StatusBadGateway)
		return
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}

	// Separate GET and POST endpoints; normalize method to uppercase.
	var getEndpoints []PluginEndpoint
	var actions []ActionInfo
	for _, ep := range found.Endpoints {
		switch strings.ToUpper(ep.Method) {
		case http.MethodGet:
			getEndpoints = append(getEndpoints, ep)
		case http.MethodPost:
			if ep.Path == "" {
				continue // skip empty-path endpoints
			}
			// Validate POST paths against traversal before exposing in template
			// URLs — the browser normalises /../ before sending, which could
			// redirect the request to an unintended route.
			if cleanPluginPath(found.RoutePrefix, ep.Path) == "" {
				continue
			}
			actionPath := ep.Path
			if !strings.HasPrefix(actionPath, "/") {
				actionPath = "/" + actionPath
			}
			actions = append(actions, ActionInfo{
				Path:        actionPath,
				Description: ep.Description,
			})
		}
	}

	// Fetch all GET endpoints concurrently with a semaphore to bound
	// the number of in-flight API calls per request.
	results := make([]EndpointData, len(getEndpoints))
	sem := make(chan struct{}, maxConcurrentAPICalls)
	var wg sync.WaitGroup
	for i, ep := range getEndpoints {
		sem <- struct{}{} // acquire
		wg.Add(1)
		go func(idx int, ep PluginEndpoint) {
			defer func() { <-sem; wg.Done() }() // release
			results[idx].Description = ep.Description
			apiPath := cleanPluginPath(found.RoutePrefix, ep.Path)
			if apiPath == "" {
				results[idx].Error = "Invalid endpoint path"
				return
			}
			var raw json.RawMessage
			if err := h.client.get(r.Context(), apiPath, &raw); err != nil {
				slog.Error("web: generic plugin fetch failed",
					"plugin", name, "path", ep.Path, "error", err)
				results[idx].Error = fmt.Sprintf("Failed to fetch: %s", err)
				return
			}
			// Pretty-print JSON for display. raw was decoded as JSON,
			// so Indent errors are unexpected but handled defensively.
			var buf bytes.Buffer
			if err := json.Indent(&buf, raw, "", "  "); err != nil {
				slog.Error("web: failed to pretty-print plugin JSON",
					"plugin", name, "path", ep.Path, "error", err)
				results[idx].Data = string(raw)
				return
			}
			results[idx].Data = buf.String()
		}(i, ep)
	}
	wg.Wait()

	data := map[string]any{
		"Page":         name,
		"Plugins":      plugins,
		"Plugin":       found,
		"EndpointData": results,
		"Actions":      actions,
		"PluginName":   name,
	}
	h.render(w, "plugin.html", data)
}

// handleGenericAction proxies POST actions through the web server so the
// bearer token is applied via apiClient, not exposed to the browser.
func (h *Handler) handleGenericAction(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "plugin")
	action := chi.URLParam(r, "*") // wildcard captures the full remainder

	found, _, fetchErr := h.lookupPlugin(r, name)
	if fetchErr != nil {
		slog.Error("web: plugin registry unavailable", "error", fetchErr)
		http.Error(w, "Plugin registry unavailable", http.StatusBadGateway)
		return
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}

	// Verify the action is a declared POST endpoint and derive apiPath from
	// the endpoint metadata rather than reconstructing from URL params.
	var apiPath string
	for _, ep := range found.Endpoints {
		if strings.EqualFold(ep.Method, http.MethodPost) && strings.TrimPrefix(ep.Path, "/") == action {
			apiPath = cleanPluginPath(found.RoutePrefix, ep.Path)
			break
		}
	}
	if apiPath == "" {
		http.NotFound(w, r)
		return
	}

	err := h.client.post(r.Context(), apiPath, nil, nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err != nil {
		slog.Error("web: generic plugin action failed",
			"plugin", name, "action", action, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		safeErr := html.EscapeString(err.Error())
		//nolint:errcheck // HTTP response write
		_, _ = w.Write([]byte(`<div class="alert alert-error">Action failed: ` + safeErr + `</div>`))
		return
	}

	//nolint:errcheck // HTTP response write
	_, _ = w.Write([]byte(`<div class="alert alert-success">Action completed successfully</div>`))
}

// ---------- Dashboard ----------

// handleDashboard renders the main dashboard with system info.
// Only one API call — no semaphore needed.
func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	var node NodeInfo
	nodeErr := h.client.get(r.Context(), "/api/v1/node", &node)
	if nodeErr != nil {
		slog.Error("web: failed to fetch node info", "error", nodeErr)
	}

	data := map[string]any{
		"Page":    "dashboard",
		"Node":    node,
		"NodeErr": nodeErr,
	}
	// Reuse dashboard NodeInfo for sidebar to avoid a second /api/v1/node call.
	if nodeErr == nil {
		data["SidebarNode"] = node
		data["SidebarConnected"] = true
	}
	h.render(w, "dashboard.html", h.withPlugins(r, data))
}

// ---------- Update plugin ----------

// handleUpdate renders the update manager page.
// Fixed 3 goroutines — no semaphore needed.
func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	var (
		pending   []PendingUpdate
		runStatus RunStatus
		config    UpdateConfig
		statusErr error
		logsErr   error
		configErr error
	)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		statusErr = h.client.get(r.Context(), "/api/v1/plugins/update/status", &pending)
	}()
	go func() {
		defer wg.Done()
		logsErr = h.client.get(r.Context(), "/api/v1/plugins/update/logs", &runStatus)
	}()
	go func() {
		defer wg.Done()
		configErr = h.client.get(r.Context(), "/api/v1/plugins/update/config", &config)
	}()
	wg.Wait()

	if statusErr != nil {
		slog.Error("web: failed to fetch pending updates", "error", statusErr)
	}
	if logsErr != nil {
		slog.Error("web: failed to fetch update logs", "error", logsErr)
	}
	if configErr != nil {
		slog.Error("web: failed to fetch update config", "error", configErr)
	}

	// Cap log size to prevent excessive memory use on ARM devices.
	// Truncate on a UTF-8 rune boundary to avoid splitting multi-byte characters.
	const maxLogBytes = 256 << 10 // 256 KB
	if len(runStatus.Log) > maxLogBytes {
		cut := maxLogBytes
		for cut > 0 && !utf8.RuneStart(runStatus.Log[cut]) {
			cut--
		}
		runStatus.Log = runStatus.Log[:cut] + "\n…(truncated)"
	}

	// Compute counts from the pending list.
	securityCount := 0
	for _, p := range pending {
		if p.Security {
			securityCount++
		}
	}

	data := map[string]any{
		"Page":          "update",
		"Pending":       pending,
		"PendingCount":  len(pending),
		"SecurityCount": securityCount,
		"RunStatus":     runStatus,
		"StatusErr":     statusErr,
		"LogsErr":       logsErr,
		"Config":        config,
		"ConfigErr":     configErr,
	}
	h.render(w, "update.html", h.withPlugins(r, data))
}

// handleUpdateRun triggers an update via the API and returns a status fragment.
func (h *Handler) handleUpdateRun(w http.ResponseWriter, r *http.Request) {
	updateType := r.FormValue("type")
	// Validate against allowlist to prevent XSS.
	switch updateType {
	case "security":
		// valid
	default:
		updateType = "full"
	}

	apiPath := "/api/v1/plugins/update/run"
	payload, err := json.Marshal(map[string]string{"type": updateType})
	if err != nil {
		slog.Error("web: failed to marshal update request", "error", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		//nolint:errcheck // HTTP response write — no recovery possible
		_, _ = w.Write([]byte(`<div class="alert alert-error">Internal error</div>`))
		return
	}
	body := bytes.NewReader(payload)

	err = h.client.post(r.Context(), apiPath, body, nil)
	if err != nil {
		slog.Error("web: failed to trigger update", "type", updateType, "error", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// html.EscapeString on error message for defense in depth.
		safeErr := html.EscapeString(err.Error())
		//nolint:errcheck // HTTP response write — no recovery possible
		_, _ = w.Write([]byte(`<div class="alert alert-error">Failed to start ` +
			updateType + ` update: ` + safeErr + `</div>`))
		return
	}

	// Return progress polling fragment. HTMX will auto-poll until done.
	jobID := "update." + updateType
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]string{
		"JobID":     jobID,
		"Status":    "running",
		"ReturnURL": "/update",
	}
	if err := h.templates["progress.html"].Execute(w, data); err != nil {
		slog.Error("web: failed to render progress", "error", err)
	}
}

// validJobID matches job IDs in the {plugin}.{job} dot-notation.
var validJobID = regexp.MustCompile(`^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$`)

// handleProgress polls the core job API and returns an HTMX fragment showing
// the current run state. While the job is running the fragment includes
// hx-trigger="every 2s" so HTMX re-polls automatically. When the job
// completes or fails the polling stops. This endpoint is plugin-agnostic:
// any job ID registered with the core scheduler works.
func (h *Handler) handleProgress(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("job")
	if !validJobID.MatchString(jobID) {
		slog.Warn("web: invalid job id in progress poll", "job", jobID, "remote_addr", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		safeJobID := html.EscapeString(jobID)
		//nolint:errcheck // HTTP response write — no recovery possible
		_, _ = w.Write([]byte(
			`<div class="alert alert-error">Invalid job ID: ` + safeJobID + `</div>`))
		return
	}

	returnURL := r.URL.Query().Get("return")
	if returnURL == "" {
		// Default: derive from plugin name (first segment of job ID).
		plugin := jobID[:strings.Index(jobID, ".")]
		returnURL = "/" + plugin
	}

	// Restrict return URL to relative paths to prevent open redirects.
	// This is the sole URL-safety gate — html/template does not sanitise
	// custom attributes like hx-get (only href/src/action).
	// Block backslash: browsers (WHATWG URL spec) normalise \ to /, so
	// "/\evil.com" becomes "//evil.com" (protocol-relative off-origin).
	if !strings.HasPrefix(returnURL, "/") || strings.HasPrefix(returnURL, "//") || strings.Contains(returnURL, `\`) {
		returnURL = "/"
	}
	// Reject non-UTF-8 and control characters to avoid surprising
	// behaviour when reflected into hx-get attributes.
	if !utf8.ValidString(returnURL) {
		returnURL = "/"
	} else {
		for _, ch := range returnURL {
			if unicode.IsControl(ch) {
				returnURL = "/"
				break
			}
		}
	}

	var run JobRun
	err := h.client.get(r.Context(), "/api/v1/jobs/"+jobID+"/runs/latest", &run)
	if err != nil {
		slog.Warn("web: failed to poll job progress", "job", jobID, "error", err)
		run = JobRun{JobID: jobID, Status: "error", Error: err.Error()}
	}

	// Use the validated request jobID as authoritative value for rendering,
	// not the API response's job_id which could differ or be empty.
	if run.JobID != "" && run.JobID != jobID {
		slog.Warn("web: job id mismatch in progress poll", "expected", jobID, "got", run.JobID)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]string{
		"JobID":     jobID,
		"Status":    run.Status,
		"StartedAt": run.StartedAt,
		"Duration":  run.Duration,
		"Error":     run.Error,
		"ReturnURL": returnURL,
	}
	if err := h.templates["progress.html"].Execute(w, data); err != nil {
		slog.Error("web: failed to render progress", "error", err)
	}
}

// cronShortcuts are the standard @-shortcuts accepted by the core scheduler.
var cronShortcuts = map[string]bool{
	"@yearly": true, "@annually": true, "@monthly": true,
	"@weekly": true, "@daily": true, "@midnight": true, "@hourly": true,
}

// validateWebCronExpr checks that expr is a valid cron expression structurally.
// It accepts the standard 5-field format, @-shortcuts, and empty strings (to
// clear a schedule).
func validateWebCronExpr(expr string) error {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil // empty = clear schedule
	}
	if cronShortcuts[strings.ToLower(trimmed)] {
		return nil
	}
	fields := strings.Fields(trimmed)
	if len(fields) != 5 {
		return fmt.Errorf(
			"Invalid schedule: expected 5 fields (minute hour dom month dow), got %d"+
				"; if your expression has a seconds field, remove it",
			len(fields))
	}
	return nil
}

// handleUpdateSettings saves individual update plugin settings via the
// settings API and returns an htmx HTML fragment with the result.
func (h *Handler) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<div class="alert alert-error">Invalid form data</div>`)) //nolint:errcheck // HTTP write
		return
	}

	type settingChange struct {
		key   string
		value any
	}

	var changes []settingChange

	// Schedule: compare against original to detect actual changes.
	// An empty schedule when the original was non-empty means the user cleared it.
	schedule := r.FormValue("schedule")
	origSchedule := r.FormValue("schedule_original")
	if schedule != origSchedule {
		if err := validateWebCronExpr(schedule); err != nil {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			safeErr := html.EscapeString(err.Error())
			_, _ = w.Write([]byte(`<div class="alert alert-error">` + safeErr + `</div>`)) //nolint:errcheck // HTTP write
			return
		}
		changes = append(changes, settingChange{key: "schedule", value: schedule})
	}

	if v := r.FormValue("auto_security"); v == "true" || v == "false" {
		if orig := r.FormValue("auto_security_original"); orig == "" || orig != v {
			changes = append(changes, settingChange{key: "auto_security", value: v == "true"})
		}
	}
	if v := r.FormValue("security_source"); v == "detected" || v == "always" {
		if orig := r.FormValue("security_source_original"); orig == "" || orig != v {
			changes = append(changes, settingChange{key: "security_source", value: v})
		}
	}

	if len(changes) == 0 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<div class="alert alert-error">No valid settings provided</div>`)) //nolint:errcheck // HTTP write
		return
	}

	var (
		failedKeys  []string
		updatedKeys []string
		warnings    []string
	)
	for _, c := range changes {
		res, err := h.client.updatePluginSetting(r.Context(), "update", c.key, c.value)
		if err != nil {
			slog.Error("web: failed to update setting", "key", c.key, "error", err)
			failedKeys = append(failedKeys, c.key)
			continue
		}
		updatedKeys = append(updatedKeys, c.key)
		if res != nil && res.Warning != "" {
			warnings = append(warnings, html.EscapeString(res.Warning))
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if len(failedKeys) > 0 && len(updatedKeys) == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<div class="alert alert-error">Failed to save settings</div>`)) //nolint:errcheck // HTTP write
		return
	}

	var b strings.Builder
	if len(failedKeys) > 0 {
		b.WriteString(`<div class="alert alert-error">`) //nolint:errcheck // strings.Builder
		_, _ = fmt.Fprintf(&b, "Updated %s but failed to update %s",
			strings.Join(updatedKeys, ", "), strings.Join(failedKeys, ", ")) //nolint:errcheck // strings.Builder
		b.WriteString(`</div>`) //nolint:errcheck // strings.Builder
	} else {
		w.Header().Set("HX-Refresh", "true")
		b.WriteString(`<div class="alert alert-success">Settings updated successfully</div>`) //nolint:errcheck // strings.Builder
	}
	for _, warn := range warnings {
		b.WriteString(`<div class="alert alert-warning">`) //nolint:errcheck // strings.Builder
		_, _ = fmt.Fprintf(&b, "Warning: %s", warn)        //nolint:errcheck // strings.Builder
		b.WriteString(`</div>`)                            //nolint:errcheck // strings.Builder
	}
	_, _ = w.Write([]byte(b.String())) //nolint:errcheck // HTTP write
}

// ---------- Network plugin ----------

// handleNetwork renders the network info page.
// Fixed 3 goroutines — no semaphore needed.
func (h *Handler) handleNetwork(w http.ResponseWriter, r *http.Request) {
	var (
		ifaces    []NetworkInterface
		status    NetworkStatus
		dns       DNSConfig
		ifaceErr  error
		statusErr error
		dnsErr    error
	)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		ifaceErr = h.client.get(r.Context(), "/api/v1/plugins/network/interfaces", &ifaces)
	}()
	go func() {
		defer wg.Done()
		statusErr = h.client.get(r.Context(), "/api/v1/plugins/network/status", &status)
	}()
	go func() {
		defer wg.Done()
		dnsErr = h.client.get(r.Context(), "/api/v1/plugins/network/dns", &dns)
	}()
	wg.Wait()

	if ifaceErr != nil {
		slog.Error("web: failed to fetch interfaces", "error", ifaceErr)
	}
	if statusErr != nil {
		slog.Error("web: failed to fetch network status", "error", statusErr)
	}
	if dnsErr != nil {
		slog.Error("web: failed to fetch DNS config", "error", dnsErr)
	}

	data := map[string]any{
		"Page":      "network",
		"Ifaces":    ifaces,
		"IfaceErr":  ifaceErr,
		"Status":    status,
		"StatusErr": statusErr,
		"DNS":       dns,
		"DNSErr":    dnsErr,
	}
	h.render(w, "network.html", h.withPlugins(r, data))
}
