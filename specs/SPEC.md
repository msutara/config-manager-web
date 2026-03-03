# Config Manager Web UI Specification

## Purpose

Provide a browser-accessible dashboard for managing headless Debian nodes,
mirroring the TUI functionality without requiring SSH access.

## Architecture

### Module Design

The web package exports a single constructor:

```go
func NewHandler(apiURL, authToken string) http.Handler
```

- **apiURL** — base URL of the CM JSON API (e.g. `http://localhost:7788`)
- **authToken** — Bearer token for API authentication (empty disables auth)

The returned handler is a Chi sub-router that core mounts at `/`.

### Static Assets

Templates and static files are embedded via `go:embed` at compile time.
No external file dependencies at runtime.

## Routes

| Route | Method | Auth | Description |
| --- | --- | --- | --- |
| `/` | GET | Yes | Dashboard with system info |
| `/login` | GET | No | Login form |
| `/auth/login` | POST | No | Validate token, set session cookie |
| `/auth/logout` | POST | Yes | Clear session cookie |
| `/update` | GET | Yes | Update manager page |
| `/update/run` | POST | Yes | Trigger update (htmx fragment) |
| `/update/settings` | POST | Yes | Save update plugin settings (htmx fragment) |
| `/network` | GET | Yes | Network information page |
| `/static/*` | GET | No | Embedded static assets |

## Authentication

### Cookie-Based Sessions

1. User visits any protected route without a valid cookie
2. Middleware redirects to `/login`
3. User enters the Bearer token in the login form
4. POST `/auth/login` validates the token against the configured `authToken`
5. On success, sets an httpOnly cookie (`cm_session`) with the token value
6. Cookie has `SameSite=Strict`, 24-hour expiry
7. Subsequent requests validated by comparing cookie value to `authToken`
8. When `authToken` is empty, all routes are accessible without login

### Security Properties

- httpOnly cookie prevents JavaScript access
- SameSite=Strict prevents CSRF
- Constant-time comparison prevents timing attacks
- No auth mode for localhost-only development

## Pages

### Dashboard (`/`)

Displays:

- Hostname
- Operating system
- CPU architecture
- Uptime (auto-refreshes every 30 seconds via htmx)

Data source: `GET /api/v1/node`

### Update Manager (`/update`)

Displays:

- Current status (running/idle)
- Pending update count
- Security update count
- Last run time and result
- Configuration (security source availability, auto-update setting, schedule)

Actions:

- **Run Full Update** — `POST /api/v1/plugins/update/run`
- **Run Security Update** — `POST /api/v1/plugins/update/run?type=security`
  (only shown when security source is available)

Settings (editable form with htmx):

- **Schedule** — cron expression (text input)
- **Auto Security Updates** — enabled/disabled (select)
- **Security Source** — detected/always (select)

Each setting change calls `PUT /api/v1/plugins/update/settings` with `{key, value}`.
The form submits via htmx and displays success/error/warning messages inline.
On success the handler sets `HX-Refresh: true` so the browser reloads the page
with fresh config values from the API.
All three fields use hidden `*_original` inputs (`schedule_original`,
`auto_security_original`, `security_source_original`) to detect changes;
unchanged fields are not re-submitted, avoiding redundant API calls.
Clearing the schedule (empty value when original was non-empty) sends an
explicit empty value to the API.
Input validation rejects invalid enum values (auto_security must be `true`/`false`,
security_source must be `detected`/`always`).
All API-provided data (errors, warnings) is escaped with `html.EscapeString` before
rendering to prevent XSS.

Data sources:

- `GET /api/v1/plugins/update/status`
- `GET /api/v1/plugins/update/config`
- `GET /api/v1/plugins/update/logs`

### Network (`/network`)

Displays:

- Connectivity status (online/offline)
- DNS resolution status
- Public IP address
- Interface table (name, type, state, address, gateway)
- DNS server list and search domains

Data sources:

- `GET /api/v1/plugins/network/status`
- `GET /api/v1/plugins/network/interfaces`
- `GET /api/v1/plugins/network/dns`

## htmx Patterns

### Dynamic Updates

- Uptime refresh: `hx-get="/" hx-trigger="every 30s" hx-select=".uptime-value"`
- Update trigger: `hx-post="/update/run" hx-target="#update-result"`
- Loading indicator: `hx-indicator="#update-spinner"`

### Response Fragments

POST handlers return HTML fragments (not full pages) for htmx to swap
into the target element. This avoids full page reloads.

## Styling

- Dark theme via embedded CSS stylesheet using custom properties for the colour palette
- Responsive layout with collapsible sidebar on mobile
- No CSS framework dependency

## Error Handling

- API errors displayed as alert banners on the relevant page
- Template render errors logged and return 500
- Default-show behavior: pages render with error messages rather than blank
