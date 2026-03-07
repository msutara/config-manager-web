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
- Cookie-based authentication using the same Bearer token as the API
- Responsive dark theme — works on phones, tablets, and desktops
- Server-rendered with htmx — no JavaScript build step required
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
