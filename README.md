# config-manager-web

Browser-based dashboard for
[Config Manager](https://github.com/msutara/config-manager-core). Designed for
headless Debian-based nodes (Raspbian Bookworm ARM, Debian Bullseye slim).

## Features

- Dashboard with hostname, OS, architecture, and live uptime
- Update manager — pending counts, package list, log viewer, run full or
  security-only updates with confirmation dialogs
- **Job progress polling** — after triggering long-running jobs, shows
  real-time status with auto-polling until completion or failure
- Network info — interfaces, connectivity status, DNS configuration
- **Network management** — set static IP, set DNS servers, delete static IP,
  rollback interface, rollback DNS with confirmation dialogs
- Cookie-based authentication using the same Bearer token as the API
- Responsive dark theme — works on phones, tablets, and desktops
- Server-rendered with htmx — no JavaScript build step required
- **Write-policy awareness** — network write operations denied by interface
  policy show a warning-level toast with actionable guidance instead of a
  generic error
- **Skeleton loading** — pages render instant skeleton placeholders, then
  htmx lazy-loads data from fragment endpoints for perceived performance
- Dynamic plugin sidebar — auto-discovers plugins from the core API registry
- Sidebar system info — hostname, uptime, and API connection indicator

## Architecture

### Plugin list caching

The sidebar plugin list is cached with a **30-second TTL** to avoid repeated
API calls on every page load. When the TTL expires, the next request refreshes
the cache from the core API. A **refresh mutex** prevents thundering-herd: if
multiple requests arrive while the cache is expired, only one goroutine fetches
from the API while the others wait and then read the refreshed cache.

### Node info caching

The `/api/v1/node` response is cached with a **5-second TTL** to deduplicate
calls when the sidebar and a fragment endpoint both need node data within the
same page load cycle. This prevents redundant API traffic on dashboard loads.

### Sidebar resilience

The sidebar degrades gracefully when the core API is unavailable:

1. **Fresh cache** — served directly, no API call.
2. **Expired (stale) cache** — if the API fetch fails, the last-known plugin
   list is returned regardless of TTL expiry, keeping the sidebar populated.
3. **No cached data at all** — the template displays a "plugins unavailable"
   message instead of an empty sidebar.

### Concurrency limits

Generic plugin pages fetch all GET endpoints concurrently. A **semaphore**
(channel of size 10) caps the number of in-flight API calls per request,
preventing a plugin with many endpoints from overwhelming the core API.

### Response body limit

Every API response is capped at **2 MB** before JSON decoding
(`maxResponseBytes` in `apiclient.go`). This prevents unbounded memory
allocation on ARM devices with limited RAM. Oversized responses return a
descriptive error; the constant is a single-line change if it needs tuning.

### Request body limit

All POST handlers for network write operations use `MaxBytesReader` to cap
incoming form data at **1 MB** (`maxFormBytes` in `routes_network.go`). This
prevents oversized submissions from consuming memory on resource-constrained
ARM devices. Requests exceeding the limit receive an inline error with a toast
notification.

### Network write error handling

`writeNetworkError` in `routes_network.go` renders inline alerts with
expandable details and an out-of-band toast notification. It distinguishes
**403 Forbidden** responses from other errors:

- **403** — the toast level is downgraded from `error` to `warning`, and the
  title is overridden to "Interface protected by policy" so the user sees
  actionable guidance instead of a scary red error.
- **All other errors** — rendered as `error`-level alerts with the original
  operation title (e.g. "Failed to set static IP for eth0").

The `toastLevel` variable is validated against a whitelist (`"error"` /
`"warning"`) before being interpolated into the HTML class attribute. This
prevents CSS-class injection if future code paths introduce new levels
without sanitization. The `toastOOB` helper applies a second whitelist for
defense in depth.

### RoutePrefix validation

Plugin registry entries include a `RoutePrefix` used to build API paths.
Before caching, each prefix is validated: it must start with `/`, must not
contain path-traversal sequences (`..`, including percent-encoded variants),
and must not contain control characters. Entries that fail validation are
dropped with a warning log.

## Documentation

- [Usage Guide](docs/USAGE.md) — accessing the web UI, page descriptions
- [Specification](specs/SPEC.md) — routes, auth flow, htmx patterns

## Development

```bash
# lint
golangci-lint run

# test
go test ./...
```

CI runs automatically on push/PR to `main` via GitHub Actions
(`.github/workflows/ci.yml`).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

See [LICENSE](LICENSE) for details.
