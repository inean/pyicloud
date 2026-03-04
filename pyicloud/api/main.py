"""Run the pyicloud FastAPI application."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.getenv("PYICLOUD_API_HOST", "127.0.0.1")
    port = int(os.getenv("PYICLOUD_API_PORT", "8000"))
    uvicorn.run("pyicloud.api.app:create_app", host=host, port=port, factory=True)


if __name__ == "__main__":
    main()
