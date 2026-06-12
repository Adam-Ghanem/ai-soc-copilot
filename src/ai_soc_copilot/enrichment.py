from __future__ import annotations

from .models import SecurityEvent

_HIGH_VALUE_HOST_HINTS = ("dc", "idm", "vpn", "fw", "siem", "backup")
_SERVICE_ACCOUNTS = ("svc_", "service_", "backup_")


def enrich_event(event: SecurityEvent) -> dict[str, str]:
    enrichment: dict[str, str] = {}
    host_lower = event.host.lower()
    user_lower = event.user.lower()

    enrichment["asset_role"] = "high-value" if any(hint in host_lower for hint in _HIGH_VALUE_HOST_HINTS) else "standard"
    enrichment["account_type"] = "service" if user_lower.startswith(_SERVICE_ACCOUNTS) else "human"
    enrichment["data_source"] = event.source

    destination = event.attributes.get("destination")
    if isinstance(destination, str):
        enrichment["destination_type"] = "external" if event.attributes.get("external") is True else "internal-or-unknown"

    return enrichment
