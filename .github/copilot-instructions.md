# Copilot Instructions

## Project Overview

Config Manager Web is the browser-based dashboard for Config Manager. It provides
an htmx + Go html/template UI served alongside the JSON API on the same port (7788).

Target platforms: Raspbian Bookworm (ARM), Debian Bullseye slim (ARM).

## Architecture

- **Entry point**: `web.go` — `NewHandler(apiURL, authToken)` returns `http.Handler`
- **Auth**: `auth.go` — cookie-based sessions, token validation
- **Routes**: `routes.go` — dashboard, update, network page handlers
- **API client**: `apiclient.go` — internal HTTP client for CM JSON API
- **Embed**: `embed.go` — `go:embed` for templates and static assets
- **Templates**: `templates/` — Go html/template files with htmx attributes
- **Static**: `static/` — htmx.min.js (vendored), style.css

## Integration with Core

Core's `server.go` mounts the web handler:

```go
import web "github.com/msutara/config-manager-web"
webHandler := web.NewHandler(apiBaseURL, authToken)
r.Mount("/", webHandler)
```

The web handler makes HTTP requests to the same server's API endpoints
(`/api/v1/*`) using the configured auth token.

## Key Patterns

- **htmx over JSON**: Page handlers return HTML, htmx handles dynamic updates
- **go:embed**: Templates and static assets compiled into the binary
- **Cookie auth**: Token entered once, stored in httpOnly cookie
- **API proxy**: Web handlers call the JSON API internally, render HTML results
- **No JS build step**: htmx is vendored, no npm/webpack/vite needed

## Conventions

- Go 1.24, golangci-lint
- `log/slog` for structured logging
- Tests use `net/http/httptest`
- Feature branches + PRs to main
- Markdownlint for documentation
