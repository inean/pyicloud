# Code samples

## HTTP API flow

```bash
# 1) login
curl -sS http://127.0.0.1:8000/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"you@example.com","password":"***"}'

# 2) session
curl -sS http://127.0.0.1:8000/v1/auth/session \
  -H "authorization: Bearer <token>"

# 3) devices
curl -sS http://127.0.0.1:8000/v1/devices \
  -H "authorization: Bearer <token>"
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
