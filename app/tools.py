"""Synthetic evidence tools exposed to the incident agent."""
from __future__ import annotations

from typing import Any, Callable, Dict, List

from app.collector import SignalCollectionResult


TOOL_NAMES = (
    "get_dashboard_metrics",
    "get_status_page",
    "get_health_check",
    "get_logs",
    "get_recent_changes",
)


def build_toolset(
    collection: SignalCollectionResult,
) -> tuple[List[Dict[str, Any]], Callable[[str, Dict[str, Any]], List[Dict[str, Any]]]]:
    groups = {
        "get_dashboard_metrics": {"metric"},
        "get_status_page": {"status_page"},
        "get_health_check": {"health_check"},
        "get_logs": {"log"},
        "get_recent_changes": {"change"},
    }
    tools = [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": f"Retrieve the collected {name.removeprefix('get_').replace('_', ' ')} evidence for this incident.",
                "parameters": {
                    "type": "object",
                    "properties": {"incident_id": {"type": "string"}},
                    "required": ["incident_id"],
                },
            },
        }
        for name in TOOL_NAMES
    ]

    def execute(name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        if name not in groups:
            raise ValueError(f"Unknown evidence tool: {name}")
        if arguments.get("incident_id") != collection.incident_id:
            raise ValueError("Tool incident_id does not match the active incident.")
        selected = [s for s in collection.signals if s.source_type in groups[name]]
        return [
            {
                "signal_id": signal.signal_id,
                "source_url": signal.url,
                "source_id": signal.source_id,
                "value": signal.value,
                "unit": signal.unit,
                "source_updated_at": signal.source_updated_at,
                "retrieved_at": signal.retrieved_at,
                "age_seconds": signal.age_seconds,
                "cached": signal.is_cached,
                "stale": signal.is_stale,
                "evidence_origin": signal.evidence_origin,
                "retrieval_status": signal.retrieval_status,
            }
            for signal in selected
        ]

    return tools, execute
