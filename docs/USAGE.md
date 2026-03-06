# Config Manager Web UI Usage

## Requirements

- **config-manager-core ≥ v0.4.0** — the web UI uses the core's async jobs
  API (`POST /api/v1/jobs/trigger`) for update operations.  Older core
  versions do not expose this endpoint and update actions will fail.

## Accessing the Web UI

When the web module is enabled, visit `http://<device-ip>:7788/` in any browser
on the same network.

### Authentication

If a Bearer token is configured, you will be redirected to the login page.
Enter the same token used for API access. The session lasts 24 hours.

### Pages

#### Dashboard

The landing page shows system information:

- **Hostname** — device name
- **OS** — operating system and version
- **Architecture** — CPU architecture (arm, arm64, amd64)
- **Uptime** — auto-refreshes every 30 seconds

#### Update Manager

View pending updates, trigger operations, and edit settings:

- **Pending Updates** — number of packages with available updates
- **Security Updates** — security-specific updates (when security source available)
- **Package List** — table of individual pending packages showing name, current
  version, new version, and a security badge for security-related updates
- **Last Run** — type, status, timestamp, duration, and package count
- **Log Viewer** — collapsible section showing raw log output from the last run
- **Run Full Update** — triggers `apt-get upgrade` for all packages (confirmation
  dialog prevents accidental clicks).  Uses the core's async jobs API
  (`POST /api/v1/jobs/trigger`) so the scheduler tracks the run and progress
  polling shows real-time status.
- **Run Security Update** — triggers security-only update with confirmation
  (hidden on systems without a separate security repository)

After triggering an update, a **progress indicator** appears showing real-time
job status.  Under normal conditions, the page polls `/progress` every 2 seconds
to check the core API until the job completes or fails.  If a poll returns an
error, the UI automatically backs off and polls less frequently (about every
5 seconds).  After 30 consecutive errors (~2.5 minutes) polling stops with a
"please refresh" message to avoid wasting resources when the core is down.
On completion, the update page reloads automatically to show updated Last Run
status.  This progress mechanism is generic — any plugin that registers
scheduled jobs with the core will benefit from it.

##### Edit Settings

Below the actions, the **Edit Settings** form allows changing:

- **Cron Schedule** — when automated updates run (e.g. `0 3 * * *` for 3 AM daily)
- **Auto Security Updates** — enable or disable automatic security updates
- **Security Source** — whether to use `detected` (OS-provided) or `always` check

Changes are saved immediately via the core API and take effect on next schedule tick.
Only fields that differ from their original values are sent, preventing redundant API
calls. Clearing the schedule (removing the value) sends an explicit empty update.
Success, error, and warning messages appear inline above the form.

#### Network

View network interface and connectivity information:

- **Connectivity** — online/offline status
- **DNS** — whether DNS resolution is working
- **Interfaces** — table of network interfaces with state, address, gateway
- **DNS Servers** — configured nameservers and search domains

#### Generic Plugin Pages

Any plugin registered with CM Core whose name matches `[a-z][a-z0-9-]*`
is automatically accessible via `/{plugin-name}` in the web UI, with actions
rendered dynamically from plugin metadata, **unless** that path conflicts with
an existing built-in route. Built-in routes (such as `/login`, `/update`,
`/network`) always take precedence. Plugin POST actions show a confirmation
dialog before executing. Plugin actions that require POSTs are
exposed under `/{plugin-name}/actions/<action-path>` and invoked by the UI.
The Update and Network pages above are hardcoded examples; additional plugins
that follow the naming rule and do not conflict with built-in routes appear
without code changes.

## Sidebar

The sidebar is present on every page and shows:

- **Navigation links** — Dashboard, Update, Network, plus any registered plugins
- **Connection indicator** — green dot when the core API is reachable
- **Hostname** — device name fetched from the core API
- **Uptime** — human-readable uptime (e.g. "up 2d 5h 30m")
- **Logout** — button to end the authenticated session

When the core API is unreachable, the sidebar degrades gracefully: navigation
links use a stale cache and the host/uptime section is hidden.

## Browser Support

The web UI works in any modern browser (Chrome, Firefox, Safari, Edge).
htmx 2.0 requires no polyfills. Mobile-responsive layout adapts to phones
and tablets.

## Security Notes

- The session cookie is httpOnly (not accessible to JavaScript)
- SameSite=Strict prevents cross-site request forgery
- For production use, configure a strong random token
- The web UI is intended for LAN access only

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| "response body exceeds … byte limit" | API response larger than 2 MB | Reduce payload at the source or raise `maxResponseBytes` in `apiclient.go` |
| Empty log section after a large upgrade | Log response exceeded 2 MB wire limit | Logs are still available via the core API directly (`curl /api/v1/plugins/update/logs`) |
| "Failed to check job status" in progress | Core API unreachable while polling job | Verify the core service is running; the job may still complete in the background |
| Progress spinner never stops | Core job stuck in "running" state | Check core logs; the job goroutine may have panicked without updating status |
