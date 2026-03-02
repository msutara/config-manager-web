# Config Manager Web UI Usage

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
- **Run Full Update** — triggers `apt-get upgrade` for all packages
- **Run Security Update** — triggers security-only update (hidden on systems
  without a separate security repository, such as Raspberry Pi OS)

##### Edit Settings

Below the actions, the **Edit Settings** form allows changing:

- **Cron Schedule** — when automated updates run (e.g. `0 3 * * *` for 3 AM daily)
- **Auto Security Updates** — enable or disable automatic security updates
- **Security Source** — whether to use `available` (OS-provided) or `always` check

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

Any plugin registered with CM Core is automatically accessible via
`/{plugin-name}` in the web UI, with actions rendered dynamically from
plugin metadata. The Update and Network pages above are hardcoded examples;
additional plugins appear without code changes.

## Browser Support

The web UI works in any modern browser (Chrome, Firefox, Safari, Edge).
htmx 2.0 requires no polyfills. Mobile-responsive layout adapts to phones
and tablets.

## Security Notes

- The session cookie is httpOnly (not accessible to JavaScript)
- SameSite=Strict prevents cross-site request forgery
- For production use, configure a strong random token
- The web UI is intended for LAN access only
