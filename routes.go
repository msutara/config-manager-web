package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
)

// ---------- Toast notifications ----------

// Toast represents a brief notification shown at the top of the viewport.
type Toast struct {
	Level   string // "success", "error", "warning"
	Message string
}

// toastOOB returns an htmx out-of-band swap fragment that injects a toast
// into #toast-container. The toast auto-dismisses via CSS animation.
func toastOOB(level, message string) string {
	switch level {
	case "success", "error", "warning":
	default:
		level = "error"
	}
	role := "status"
	if level == "error" {
		role = "alert"
	}
	safeMsg := html.EscapeString(message)
	return `<output class="toast toast-` + level + `" role="` + role +
		`" hx-swap-oob="afterbegin:#toast-container">` + safeMsg + `</output>`
}

// flashToast maps flash query-parameter values to toast content.
var flashToast = map[string]*Toast{
	"settings-saved":   {Level: "success", Message: "Settings saved successfully"},
	"settings-partial": {Level: "warning", Message: "Settings saved with warnings"},
	"action-ok":        {Level: "success", Message: "Action completed successfully"},
	"network-applied":  {Level: "success", Message: "Network configuration applied"},
	"network-deleted":  {Level: "success", Message: "Static IP removed, reverted to DHCP"},
	"network-rollback": {Level: "success", Message: "Configuration rolled back"},
}

// parseFlashToast returns a Toast if the request contains a recognised flash param.
func parseFlashToast(r *http.Request) *Toast {
	return flashToast[r.URL.Query().Get("flash")]
}

// renderFragment executes a standalone fragment template (no layout wrapper)
// and writes the HTML result. Used by lazy-loading fragment endpoints.
func (h *Handler) renderFragment(w http.ResponseWriter, name string, data any) {
	t, ok := h.templates[name]
	if !ok {
		slog.Error("fragment template not found", "template", name)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		slog.Error("fragment render error", "template", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes()) //nolint:errcheck // HTTP response write
}

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
	// Reject backslashes (some proxies normalize \ to /) and control characters.
	if strings.Contains(decoded, "\\") {
		return ""
	}
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
		// Fall back to stale cache so the page/fragment can still render
		// with the last-known plugin list rather than returning 502.
		// The original error is preserved so callers know data is stale.
		if cached, ok := h.cache.getAny(); ok {
			plugins = cached
		} else {
			return nil, nil, err
		}
	}
	for i := range plugins {
		if plugins[i].Name == name {
			return &plugins[i], plugins, err
		}
	}
	return nil, plugins, err
}

// handleGenericPlugin renders a generic page with skeleton placeholders.
// Actual data loads asynchronously via the /fragments/{plugin} endpoint.
func (h *Handler) handleGenericPlugin(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "plugin")

	found, plugins, fetchErr := h.lookupPlugin(r, name)
	if found == nil && len(plugins) == 0 && fetchErr != nil {
		// No plugin data available (API down, no cache).
		slog.Error("web: plugin registry unavailable", "error", fetchErr)
		http.Error(w, "Plugin registry unavailable", http.StatusBadGateway)
		return
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}

	data := map[string]any{
		"Page":           name,
		"PluginName":     name,
		"PluginTitle":    titleCase(found.Name),
		"Plugins":        plugins, // pre-populated; withPlugins will reuse
		"PluginsFetched": true,
	}
	if fetchErr != nil {
		// Signal that plugins came from stale cache so withPlugins
		// skips the node-info fetch (API is likely down).
		data["PluginsFetchFailed"] = true
	}
	if t := parseFlashToast(r); t != nil {
		data["Toast"] = t
	}
	h.render(w, "plugin.html", h.withPlugins(r, data))
}

// handlePluginFragment returns the generic plugin data as an htmx fragment.
func (h *Handler) handlePluginFragment(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "plugin")

	found, plugins, fetchErr := h.lookupPlugin(r, name)
	if found == nil && len(plugins) == 0 && fetchErr != nil {
		slog.Error("web: plugin registry unavailable", "error", fetchErr)
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
				continue
			}
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

	// Fetch all GET endpoints concurrently with a semaphore.
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
		"Plugin":       found,
		"EndpointData": results,
		"Actions":      actions,
		"PluginName":   name,
	}
	h.renderFragment(w, "frag-plugin.html", data)
}

// handleGenericAction proxies POST actions through the web server so the
// bearer token is applied via apiClient, not exposed to the browser.
func (h *Handler) handleGenericAction(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "plugin")
	action := chi.URLParam(r, "*") // wildcard captures the full remainder

	found, plugins, fetchErr := h.lookupPlugin(r, name)
	if found == nil && len(plugins) == 0 && fetchErr != nil {
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
		var safeErr string
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			safeErr = html.EscapeString(apiErr.Message)
		} else {
			safeErr = html.EscapeString(err.Error())
		}
		//nolint:errcheck // HTTP response write
		_, _ = w.Write([]byte(`<div class="alert alert-error"><strong>Action failed</strong>` +
			`<details class="error-details"><summary>Show details</summary>` +
			`<pre>` + safeErr + `</pre></details></div>` + toastOOB("error", "Action failed")))
		return
	}

	//nolint:errcheck // HTTP response write
	_, _ = w.Write([]byte(`<div class="alert alert-success">Action completed successfully</div>` +
		toastOOB("success", "Action completed")))
}

// ---------- Dashboard ----------

// handleDashboard renders the dashboard page with skeleton placeholders.
// Actual data loads asynchronously via the /fragments/dashboard endpoint.
func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Page": "dashboard"}
	if t := parseFlashToast(r); t != nil {
		data["Toast"] = t
	}
	h.render(w, "dashboard.html", h.withPlugins(r, data))
}

// handleDashboardFragment returns the dashboard data as an htmx fragment.
func (h *Handler) handleDashboardFragment(w http.ResponseWriter, r *http.Request) {
	var node NodeInfo
	var nodeErr error
	if cached, ok := h.nodes.get(); ok {
		node = cached
	} else {
		nodeErr = h.client.get(r.Context(), "/api/v1/node", &node)
		if nodeErr != nil {
			slog.Error("web: failed to fetch node info", "error", nodeErr)
		} else {
			h.nodes.set(node)
		}
	}

	data := map[string]any{
		"Node":    node,
		"NodeErr": nodeErr,
	}
	h.renderFragment(w, "frag-dashboard.html", data)
}

// ---------- Update plugin ----------

// handleUpdate renders the update manager page with skeleton placeholders.
// Actual data loads asynchronously via the /fragments/update endpoint.
func (h *Handler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Page": "update"}
	if t := parseFlashToast(r); t != nil {
		data["Toast"] = t
	}
	h.render(w, "update.html", h.withPlugins(r, data))
}

// handleUpdateFragment returns the update page data as an htmx fragment.
// Fixed 3 goroutines — no semaphore needed.
func (h *Handler) handleUpdateFragment(w http.ResponseWriter, r *http.Request) {
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
		"Pending":       pending,
		"PendingCount":  len(pending),
		"SecurityCount": securityCount,
		"RunStatus":     runStatus,
		"StatusErr":     statusErr,
		"LogsErr":       logsErr,
		"Config":        config,
		"ConfigErr":     configErr,
	}
	h.renderFragment(w, "frag-update.html", data)
}

// handleUpdateRun triggers an update via the async jobs API and returns a
// progress polling fragment.  Uses /api/v1/jobs/trigger (not the plugin's
// synchronous /run endpoint) so the scheduler records the run and progress
// polling works correctly.
func (h *Handler) handleUpdateRun(w http.ResponseWriter, r *http.Request) {
	if err := parseFormLimited(w, r); err != nil {
		writeFormError(w, err)
		return
	}

	updateType := r.FormValue("type")
	// Validate against allowlist to prevent XSS.
	switch updateType {
	case "security":
		// valid
	default:
		updateType = "full"
	}

	jobID := "update." + updateType
	payload, err := json.Marshal(map[string]string{"job_id": jobID})
	if err != nil {
		slog.Error("web: failed to marshal trigger request", "error", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		//nolint:errcheck // HTTP response write — no recovery possible
		_, _ = w.Write([]byte(`<div class="alert alert-error">Internal error</div>` +
			toastOOB("error", "Internal error")))
		return
	}
	body := bytes.NewReader(payload)

	err = h.client.post(r.Context(), "/api/v1/jobs/trigger", body, nil)
	if err != nil {
		slog.Error("web: failed to trigger update", "type", updateType, "error", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		safeErr := html.EscapeString(err.Error())
		//nolint:errcheck // HTTP response write — no recovery possible
		_, _ = w.Write([]byte(`<div class="alert alert-error"><strong>Failed to start ` +
			updateType + ` update</strong>` +
			`<details class="error-details"><summary>Show details</summary>` +
			`<pre>` + safeErr + `</pre></details></div>` +
			toastOOB("error", "Failed to start update")))
		return
	}

	// Return progress polling fragment. HTMX will auto-poll until done.
	data := map[string]string{
		"JobID":     jobID,
		"Status":    "running",
		"ReturnURL": "/update",
	}
	h.renderFragment(w, "progress.html", data)
}

// validJobID matches job IDs in the {plugin}.{job} dot-notation.
var validJobID = regexp.MustCompile(`^[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*$`)

// maxErrorRetries caps the number of consecutive poll errors before giving up.
// At 5 s between retries this allows ~2.5 minutes of transient failures.
const maxErrorRetries = 30

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

	// Track consecutive error retries via query parameter so the template
	// can stop polling after maxErrorRetries (prevents infinite retries
	// when core is down).
	retryCount := 0
	if v := r.URL.Query().Get("retry"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			retryCount = n
		}
	}

	if err != nil {
		slog.Warn("web: failed to poll job progress", "job", jobID, "retry", retryCount, "error", err)
		// Distinguish retryable (5xx/network) from non-retryable (4xx) errors.
		// Non-retryable errors use "failed" status which stops polling.
		status := "error"
		var apiErr *APIError
		if errors.As(err, &apiErr) && !apiErr.Retryable() {
			status = "failed"
		}
		// Cap retries to avoid infinite polling when core is unreachable.
		if status == "error" && retryCount >= maxErrorRetries {
			status = "failed"
			run = JobRun{JobID: jobID, Status: status, Error: "job status unknown after too many retries — please refresh the page"}
		} else {
			if status == "error" {
				retryCount++
			}
			run = JobRun{JobID: jobID, Status: status, Error: err.Error()}
		}
	} else {
		retryCount = 0 // reset on successful poll
	}

	// Use the validated request jobID as authoritative value for rendering,
	// not the API response's job_id which could differ or be empty.
	if run.JobID != "" && run.JobID != jobID {
		slog.Warn("web: job id mismatch in progress poll", "expected", jobID, "got", run.JobID)
	}

	// Completed jobs redirect back to the plugin page so the browser
	// fully re-renders widgets (e.g. "Last Run") with fresh data.
	// HX-Redirect tells htmx to do a real navigation instead of an
	// in-place swap (which broke because hx-select="body" cannot
	// extract <body> from a full HTML document fragment).
	if run.Status == "completed" {
		w.Header().Set("HX-Redirect", returnURL)
		return
	}

	data := map[string]string{
		"JobID":      jobID,
		"Status":     run.Status,
		"StartedAt":  run.StartedAt,
		"Duration":   run.Duration,
		"Error":      run.Error,
		"ReturnURL":  returnURL,
		"RetryCount": strconv.Itoa(retryCount),
	}
	h.renderFragment(w, "progress.html", data)
}

// ---------- Job history ----------

// defaultHistoryLimit is the number of runs shown per page.
const defaultHistoryLimit = 20

// handleHistory renders the job history page with skeleton placeholders.
// Actual data loads asynchronously via the /fragments/history endpoint.
func (h *Handler) handleHistory(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("job")
	if !validJobID.MatchString(jobID) {
		http.Error(w, "Invalid job ID", http.StatusBadRequest)
		return
	}
	data := map[string]any{
		"Page":  "history",
		"JobID": jobID,
	}
	h.render(w, "history.html", h.withPlugins(r, data))
}

// handleHistoryFragment returns paginated job history as an htmx fragment.
func (h *Handler) handleHistoryFragment(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("job")
	if !validJobID.MatchString(jobID) {
		http.Error(w, "Invalid job ID", http.StatusBadRequest)
		return
	}

	limit := defaultHistoryLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	runs, err := h.client.listJobRuns(r.Context(), jobID, limit, offset)

	data := map[string]any{
		"JobID": jobID,
		"Limit": limit,
	}
	if err != nil {
		slog.Error("web: failed to fetch job runs", "job", jobID, "error", err)
		data["Error"] = err.Error()
	} else {
		data["Runs"] = runs
		data["HasPrev"] = offset > 0
		if offset-limit >= 0 {
			data["PrevOffset"] = offset - limit
		} else {
			data["PrevOffset"] = 0
		}
		data["HasNext"] = len(runs) == limit
		data["NextOffset"] = offset + limit
	}
	h.renderFragment(w, "frag-history.html", data)
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
	if err := parseFormLimited(w, r); err != nil {
		writeFormError(w, err)
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
			//nolint:errcheck // HTTP write
			_, _ = w.Write([]byte(`<div class="alert alert-error">` + safeErr + `</div>` +
				toastOOB("error", "Invalid schedule")))
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
		//nolint:errcheck // HTTP write
		_, _ = w.Write([]byte(`<div class="alert alert-error">No valid settings provided</div>` +
			toastOOB("error", "No changes detected")))
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
		//nolint:errcheck // HTTP write
		_, _ = w.Write([]byte(`<div class="alert alert-error">Failed to save settings</div>` +
			toastOOB("error", "Failed to save settings")))
		return
	}

	// Full success — redirect so the page re-renders with updated config values.
	if len(failedKeys) == 0 {
		flash := "settings-saved"
		if len(warnings) > 0 {
			flash = "settings-partial"
		}
		q := url.Values{}
		q.Set("flash", flash)
		u := &url.URL{Path: "/update", RawQuery: q.Encode()}
		w.Header().Set("HX-Redirect", u.String())
		return
	}

	// Partial failure — show inline details + toast.
	var b strings.Builder
	b.WriteString(`<div class="alert alert-error">`) //nolint:errcheck // strings.Builder
	_, _ = fmt.Fprintf(&b, "Updated %s but failed to update %s",
		strings.Join(updatedKeys, ", "), strings.Join(failedKeys, ", ")) //nolint:errcheck // strings.Builder
	b.WriteString(`</div>`) //nolint:errcheck // strings.Builder
	for _, warn := range warnings {
		b.WriteString(`<div class="alert alert-warning">`) //nolint:errcheck // strings.Builder
		_, _ = fmt.Fprintf(&b, "Warning: %s", warn)        //nolint:errcheck // strings.Builder
		b.WriteString(`</div>`)                            //nolint:errcheck // strings.Builder
	}
	b.WriteString(toastOOB("warning", "Some settings could not be saved")) //nolint:errcheck // strings.Builder
	_, _ = w.Write([]byte(b.String()))                                     //nolint:errcheck // HTTP write
}

// ---------- Network plugin ----------

// handleNetwork renders the network page with skeleton placeholders.
// Actual data loads asynchronously via the /fragments/network endpoint.
func (h *Handler) handleNetwork(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"Page": "network"}
	if t := parseFlashToast(r); t != nil {
		data["Toast"] = t
	}
	h.render(w, "network.html", h.withPlugins(r, data))
}

// handleNetworkFragment returns the network data as an htmx fragment.
// Fixed 3 goroutines — no semaphore needed.
func (h *Handler) handleNetworkFragment(w http.ResponseWriter, r *http.Request) {
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
		"Ifaces":    ifaces,
		"IfaceErr":  ifaceErr,
		"Status":    status,
		"StatusErr": statusErr,
		"DNS":       dns,
		"DNSErr":    dnsErr,
	}
	h.renderFragment(w, "frag-network.html", data)
}
