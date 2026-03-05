# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Removed legacy sync surfaces

The next release after this change set is intended to be a **major** release (`2.0.0`) due to breaking public API changes.

Removed public surfaces:
- `from pyicloud import PyiCloudService`
- `pyicloud.services`
- `pyicloud.legacy`
- `pyicloud.cmdline`

Migration path:
- Use the HTTP API (`/v1/*`) and the `icloud` subcommand CLI (`pyicloud.cli.main`).
- See `README.md` migration tables for endpoint/command replacements.

### Changed

- Public docs were realigned to API/CLI-first usage.
- Legacy module path wiring was replaced with neutral adapter module paths.
- Deterministic test guardrails now block outbound network by default.
