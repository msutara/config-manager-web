package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
)

// validIfaceName matches safe interface names (alphanumeric, hyphens, dots, colons for aliases).
var validIfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]*$`)

// maxFormBytes limits POST body size for form-based handlers.
const maxFormBytes = 1 << 20 // 1 MB

// errFormTooLarge is returned by parseFormLimited when the body exceeds maxFormBytes.
var errFormTooLarge = errors.New("request body too large")

// parseFormLimited wraps r.Body in MaxBytesReader and calls ParseForm.
// Returns errFormTooLarge for oversized bodies or the original parse error
// for malformed form data.
func parseFormLimited(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		if err.Error() == "http: request body too large" {
			return errFormTooLarge
		}
		return fmt.Errorf("invalid form data: %w", err)
	}
	return nil
}

// writeNetworkError writes an inline error alert with details and an OOB toast.
// The toast shows a generic title; error details are only in the expandable block.
// If the error is an *APIError, only the message (not the internal path) is shown.
func (h *Handler) writeNetworkError(w http.ResponseWriter, title string, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	safeErr := html.EscapeString(err.Error())
	if apiErr, ok := err.(*APIError); ok {
		safeErr = html.EscapeString(apiErr.Message)
	}
	_, _ = w.Write([]byte(`<div class="alert alert-error"><strong>` + //nolint:errcheck // HTTP write
		html.EscapeString(title) + `</strong>` +
		`<details class="error-details"><summary>Show details</summary>` +
		`<pre>` + safeErr + `</pre></details></div>` +
		toastOOB("error", html.EscapeString(title))))
}

// writeFormError writes an inline alert for parseFormLimited failures.
func writeFormError(w http.ResponseWriter, err error) {
	msg := "Invalid form data"
	if errors.Is(err, errFormTooLarge) {
		msg = "Request too large"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<div class="alert alert-error">` + msg + `</div>` + //nolint:errcheck // HTTP write
		toastOOB("error", msg)))
}

// handleNetworkSetStaticIP applies a static IP configuration to an interface.
func (h *Handler) handleNetworkSetStaticIP(w http.ResponseWriter, r *http.Request) {
	if err := parseFormLimited(w, r); err != nil {
		writeFormError(w, err)
		return
	}

	name := r.FormValue("name")
	address := r.FormValue("address")
	gateway := r.FormValue("gateway")

	// Validate inputs.
	if name == "" || !validIfaceName.MatchString(name) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := `<div class="alert alert-error">Invalid interface name</div>` + toastOOB("error", "Invalid interface name")
		_, _ = w.Write([]byte(msg)) //nolint:errcheck // HTTP write
		return
	}
	if address == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := `<div class="alert alert-error">Address is required (CIDR format, e.g. 192.168.1.10/24)</div>` + toastOOB("error", "Address is required")
		_, _ = w.Write([]byte(msg)) //nolint:errcheck // HTTP write
		return
	}

	payload, err := json.Marshal(map[string]string{
		"address": address,
		"gateway": gateway,
	})
	if err != nil {
		slog.Error("web: failed to marshal static IP request", "error", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := `<div class="alert alert-error">Internal error</div>` + toastOOB("error", "Internal error")
		_, _ = w.Write([]byte(msg)) //nolint:errcheck // HTTP write
		return
	}

	var result NetworkWriteResult
	if err := h.client.putConfirm(r.Context(), "/api/v1/plugins/network/interfaces/"+name, bytes.NewReader(payload), &result); err != nil {
		slog.Error("web: failed to set static IP", "interface", name, "error", err)
		h.writeNetworkError(w, "Failed to set static IP for "+name, err)
		return
	}

	w.Header().Set("HX-Redirect", "/network?flash=network-applied")
}

// handleNetworkSetDNS applies DNS server configuration.
func (h *Handler) handleNetworkSetDNS(w http.ResponseWriter, r *http.Request) {
	if err := parseFormLimited(w, r); err != nil {
		writeFormError(w, err)
		return
	}

	servers := r.FormValue("nameservers")

	if servers == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := `<div class="alert alert-error">At least one DNS server is required</div>` + toastOOB("error", "DNS servers required")
		_, _ = w.Write([]byte(msg)) //nolint:errcheck // HTTP write
		return
	}

	// Parse comma-separated servers.
	parts := strings.Split(servers, ",")
	nameservers := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			nameservers = append(nameservers, s)
		}
	}
	if len(nameservers) == 0 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := `<div class="alert alert-error">At least one DNS server is required</div>` + toastOOB("error", "DNS servers required")
		_, _ = w.Write([]byte(msg)) //nolint:errcheck // HTTP write
		return
	}

	// Also parse optional search domains.
	searchDomains := r.FormValue("search")
	search := make([]string, 0)
	if searchDomains != "" {
		for _, s := range strings.Split(searchDomains, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				search = append(search, s)
			}
		}
	}

	payload, err := json.Marshal(map[string]any{
		"nameservers": nameservers,
		"search":      search,
	})
	if err != nil {
		slog.Error("web: failed to marshal DNS request", "error", err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := `<div class="alert alert-error">Internal error</div>` + toastOOB("error", "Internal error")
		_, _ = w.Write([]byte(msg)) //nolint:errcheck // HTTP write
		return
	}

	var result NetworkWriteResult
	if err := h.client.putConfirm(r.Context(), "/api/v1/plugins/network/dns", bytes.NewReader(payload), &result); err != nil {
		slog.Error("web: failed to set DNS", "error", err)
		h.writeNetworkError(w, "Failed to set DNS servers", err)
		return
	}

	w.Header().Set("HX-Redirect", "/network?flash=network-applied")
}

// handleNetworkDeleteStaticIP removes static IP, reverting to DHCP.
func (h *Handler) handleNetworkDeleteStaticIP(w http.ResponseWriter, r *http.Request) {
	if err := parseFormLimited(w, r); err != nil {
		writeFormError(w, err)
		return
	}

	name := r.FormValue("name")
	if name == "" || !validIfaceName.MatchString(name) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := `<div class="alert alert-error">Invalid interface name</div>` + toastOOB("error", "Invalid interface name")
		_, _ = w.Write([]byte(msg)) //nolint:errcheck // HTTP write
		return
	}

	var result NetworkWriteResult
	if err := h.client.deleteConfirm(r.Context(), "/api/v1/plugins/network/interfaces/"+name, &result); err != nil {
		slog.Error("web: failed to delete static IP", "interface", name, "error", err)
		h.writeNetworkError(w, "Failed to remove static IP for "+name, err)
		return
	}

	w.Header().Set("HX-Redirect", "/network?flash=network-deleted")
}

// handleNetworkRollbackInterface restores previous interface configuration.
func (h *Handler) handleNetworkRollbackInterface(w http.ResponseWriter, r *http.Request) {
	if err := parseFormLimited(w, r); err != nil {
		writeFormError(w, err)
		return
	}

	name := r.FormValue("name")
	if name == "" || !validIfaceName.MatchString(name) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := `<div class="alert alert-error">Invalid interface name</div>` + toastOOB("error", "Invalid interface name")
		_, _ = w.Write([]byte(msg)) //nolint:errcheck // HTTP write
		return
	}

	var result NetworkWriteResult
	if err := h.client.postConfirm(r.Context(), "/api/v1/plugins/network/interfaces/"+name+"/rollback", &result); err != nil {
		slog.Error("web: failed to rollback interface", "interface", name, "error", err)
		h.writeNetworkError(w, "Failed to rollback "+name, err)
		return
	}

	w.Header().Set("HX-Redirect", "/network?flash=network-rollback")
}

// handleNetworkRollbackDNS restores previous DNS configuration.
func (h *Handler) handleNetworkRollbackDNS(w http.ResponseWriter, r *http.Request) {
	if err := parseFormLimited(w, r); err != nil {
		writeFormError(w, err)
		return
	}

	var result NetworkWriteResult
	if err := h.client.postConfirm(r.Context(), "/api/v1/plugins/network/dns/rollback", &result); err != nil {
		slog.Error("web: failed to rollback DNS", "error", err)
		h.writeNetworkError(w, "Failed to rollback DNS", err)
		return
	}

	w.Header().Set("HX-Redirect", "/network?flash=network-rollback")
}
