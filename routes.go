package web

import (
	"html"
	"log/slog"
	"net/http"
	"sync"
)

// handleDashboard renders the main dashboard with system info.
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
	h.render(w, "dashboard.html", data)
}

// handleUpdate renders the update manager page.
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
		slog.Error("web: failed to fetch update status", "error", statusErr)
	}
	if logsErr != nil {
		slog.Error("web: failed to fetch update logs", "error", logsErr)
	}
	if configErr != nil {
		slog.Error("web: failed to fetch update config", "error", configErr)
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
	h.render(w, "update.html", data)
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

	path := "/api/v1/plugins/update/run"
	if updateType == "security" {
		path = "/api/v1/plugins/update/run?type=security"
	}

	err := h.client.post(r.Context(), path, nil)
	if err != nil {
		slog.Error("web: failed to trigger update", "type", updateType, "error", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		// html.EscapeString on error message for defense in depth.
		safeErr := html.EscapeString(err.Error())
		//nolint:errcheck // HTTP response write — no recovery possible
		_, _ = w.Write([]byte(`<div class="alert alert-error">Failed to start ` +
			updateType + ` update: ` + safeErr + `</div>`))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	//nolint:errcheck // HTTP response write — no recovery possible
	_, _ = w.Write([]byte(`<div class="alert alert-success">` +
		updateType + ` update started successfully</div>`))
}

// handleNetwork renders the network info page.
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
	h.render(w, "network.html", data)
}
