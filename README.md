---
title: pyicloud
---

# pyicloud

`pyicloud` is an API-first and CLI-first toolkit for iCloud workflows.

This repository no longer exposes legacy synchronous Python surfaces such as:
- `from pyicloud import PyiCloudService`
- `pyicloud.services`
- `pyicloud.legacy`
- `pyicloud.cmdline`

Use the HTTP API (`/v1/*`) and the `icloud` subcommand CLI instead.

## Install

```bash
uv sync --extra dev
```

## Run API

```bash
uv run python -m pyicloud.api.main
```

By default the API runs at `http://127.0.0.1:8000`.

## CLI quick start

```bash
# Login
icloud auth login --username you@example.com --password '***'

# Verify current session
icloud auth session

# Devices
icloud devices list

# Account
icloud account devices
icloud account family
icloud account storage

# Drive
icloud drive tree --path /
```

## Migration table (legacy -> current)

| Legacy surface | Current replacement |
|---|---|
| `from pyicloud import PyiCloudService` | `icloud ...` commands or direct HTTP calls to `/v1/*` |
| `pyicloud.services.*` imports | Domain endpoints under `/v1/devices`, `/v1/account`, `/v1/drive`, `/v1/calendar`, `/v1/contacts`, `/v1/reminders`, `/v1/photos`, `/v1/ubiquity` |
| `pyicloud.cmdline` | `pyicloud.cli.main` (`icloud` command) |
| `pyicloud.legacy` | Removed; use API/CLI routes and subcommands |

## Endpoint mapping examples

| Legacy intent | HTTP endpoint | CLI command |
|---|---|---|
| Login | `POST /v1/auth/login` | `icloud auth login` |
| Submit 2FA code | `POST /v1/auth/security-code` | `icloud auth security-code` |
| List devices | `GET /v1/devices` | `icloud devices list` |
| Device location | `GET /v1/devices/{device_id}/location` | `icloud devices location --device-id ...` |
| Account storage | `GET /v1/account/storage` | `icloud account storage` |
| Drive tree | `GET /v1/drive/tree` | `icloud drive tree --path ...` |
| Photo download | `GET /v1/photos/download` | `icloud photos download --asset-id ...` |

## Contract notes

- Success envelopes use: `{"data": ...}`.
- Error envelopes use: `{"error": {"code", "message", "status", "details"}}`.
- Challenge-driven auth: protected domain routes can return `auth_challenge_required` when Apple session is expired; clients complete auth via `/v1/auth/login` and `/v1/auth/security-code`, then retry the original operation.
- Provider runtime direction is locked to strict containment (Option B): legacy sync provider clients stay behind async adapters; no legacy runtime alias symbols are exposed in active adapter/runtime paths.
- Vertical tests run in-process ASGI and block external network access.

## Observability

The project includes optional observability query commands/endpoints:
- `icloud observability promql|traceql|logql`
- `/v1/observability/promql|traceql|logql`

See [docs/observability.md](docs/observability.md) for adapter and environment configuration.
