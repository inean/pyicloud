"""Compatibility shim for endpoint-restore service moved to auth context."""

from pyicloud.contexts.crosscutting.auth.application.service_endpoint_restore import ServiceEndpointRestoreService

__all__ = ["ServiceEndpointRestoreService"]
