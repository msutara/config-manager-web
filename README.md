# config-manager-web

Browser-based dashboard for
[Config Manager](https://github.com/msutara/config-manager-core). Designed for
headless Debian-based nodes (Raspbian Bookworm ARM, Debian Bullseye slim).

## Features

- Dashboard with hostname, OS, architecture, and live uptime
- Update manager — pending counts, run full or security-only updates
- Network info — interfaces, connectivity status, DNS configuration
- Cookie-based authentication using the same Bearer token as the API
- Responsive dark theme — works on phones, tablets, and desktops
- Server-rendered with htmx — no JavaScript build step required

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
