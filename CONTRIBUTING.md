# Contributing

Thank you for your interest in contributing to the Config Manager project!

## Getting Started

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Run tests: `go test ./...`
5. Run linter: `golangci-lint run`
6. Submit a pull request

## Guidelines

- Keep changes focused — one feature or fix per PR
- Write tests for new functionality
- Follow existing code style (enforced by `golangci-lint`)
- Update documentation if your change affects usage
- Commit messages should follow
  [Conventional Commits](https://www.conventionalcommits.org/)
  (e.g., `feat:`, `fix:`, `docs:`)

## Pull Request Process

1. Ensure CI passes (lint, test, markdownlint)
2. PRs are squash-merged into `main`
3. Maintainer will review and may request changes

## Project Structure

This project is split across multiple repositories:

- [config-manager-core](https://github.com/msutara/config-manager-core) —
  core framework, plugin system, API server
- [cm-plugin-update](https://github.com/msutara/cm-plugin-update) —
  OS/package update management plugin
- [cm-plugin-network](https://github.com/msutara/cm-plugin-network) —
  network configuration plugin
- [config-manager-tui](https://github.com/msutara/config-manager-tui) —
  terminal UI (Bubble Tea)
- [config-manager-web](https://github.com/msutara/config-manager-web) —
  browser-based dashboard (htmx + Go templates)

## Code of Conduct

Be respectful and constructive. We are all here to learn and build together.
