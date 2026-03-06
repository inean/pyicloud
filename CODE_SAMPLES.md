# Code samples

## HTTP API flow

```bash
# 1) start auth challenge
curl -sS http://127.0.0.1:8000/v1/auth/challenge \
  -H 'content-type: application/json' \
  -d '{"username":"you@example.com"}'

# 2) continue challenge with password
curl -sS http://127.0.0.1:8000/v1/auth/challenge \
  -H 'content-type: application/json' \
  -d '{"challenge_id":"<challenge-id>","password_envelope":"***"}'

# If response challenge_type is security_code_required:
curl -sS http://127.0.0.1:8000/v1/auth/challenge \
  -H 'content-type: application/json' \
  -d '{"challenge_id":"<challenge-id>","security_code":"123456","password_envelope":"***"}'

# 3) session
curl -sS http://127.0.0.1:8000/v1/auth/session \
  -H "authorization: Bearer <token>"

# 4) devices
curl -sS http://127.0.0.1:8000/v1/devices \
  -H "authorization: Bearer <token>"
```

## Admin allowlist (API)

```bash
# list entries (admin JWT required)
curl -sS http://127.0.0.1:8000/v1/admin/allowlist \
  -H "authorization: Bearer <admin-token>"

# add member
curl -sS http://127.0.0.1:8000/v1/admin/allowlist \
  -X POST \
  -H 'content-type: application/json' \
  -H "authorization: Bearer <admin-token>" \
  -d '{"username":"member@example.com","role":"member","status":"active"}'

# promote to admin
curl -sS http://127.0.0.1:8000/v1/admin/allowlist/member@example.com/role \
  -X POST \
  -H 'content-type: application/json' \
  -H "authorization: Bearer <admin-token>" \
  -d '{"role":"admin"}'
```

## CLI flow

```bash
icloud auth login --username you@example.com --password '***'
icloud auth session
icloud devices list
icloud devices location --device-id <device-id>
icloud account storage
icloud drive tree --path /
```

## Drive upload/download

```bash
# upload
icloud drive upload --parent-path /Documents --file ./local.txt

# download
icloud drive file --path /Documents/local.txt --download-to ./local.txt
```

## Photos and ubiquity

```bash
icloud photos albums
icloud photos assets --album "All Photos" --limit 50 --offset 0
icloud photos download --asset-id <asset-id> --download-to ./asset.bin

icloud ubiquity tree --path /
icloud ubiquity file --path /Documents/shared.txt --download-to ./shared.txt
```

## Removed legacy examples

The following legacy code samples are intentionally removed in this cycle:
- `PyiCloudService(...)`
- `pyicloud.services.*`
- `pyicloud.legacy`
- `pyicloud.cmdline`

## Internal canonical modules (for contributors)

- Provider runtime: `pyicloud.platform.provider.runtime`
- Session store: `pyicloud.platform.storage.session_store`
- Upstream telemetry helpers: `pyicloud.platform.telemetry.upstream`
- Removed shim namespaces: `pyicloud.upstream`, `pyicloud.adapters.store`, `pyicloud.adapters.services.runtime`
