"""Operator-owned canary registry and proposal-surface matching."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml


@dataclass(frozen=True)
class CanaryMarker:
    """A non-secret marker planted by an operator outside agent authority."""

    canary_id: str
    marker: str
    location_hint: str


@dataclass(frozen=True)
class CanaryMatch:
    """A marker observation without any surrounding proposal payload."""

    canary_id: str
    where_observed: str


def load_canary_registry(path: str | Path) -> tuple[CanaryMarker, ...]:
    """Load and strictly validate an operator-owned YAML/JSON registry.

    The registry is deliberately separate from the agent-facing proposal and
    policy surfaces. Deployment is responsible for keeping ``path`` outside
    the agent authority domain.
    """
    registry_path = Path(path).expanduser()
    try:
        with registry_path.open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid canary registry YAML: {exc}") from exc

    if not isinstance(document, Mapping) or set(document) != {"canaries"}:
        raise ValueError("canary registry must contain only a top-level 'canaries' list")
    entries = document["canaries"]
    if not isinstance(entries, list):
        raise ValueError("canary registry 'canaries' must be a list")

    canaries: list[CanaryMarker] = []
    seen_ids: set[str] = set()
    seen_markers: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or set(entry) != {"canary_id", "marker", "location_hint"}:
            raise ValueError(
                f"canary registry entry {index} must contain exactly canary_id, marker, and location_hint"
            )
        values = {key: entry[key] for key in ("canary_id", "marker", "location_hint")}
        if not all(isinstance(value, str) and value.strip() for value in values.values()):
            raise ValueError(f"canary registry entry {index} fields must be non-empty strings")
        if any("\x00" in value or "\r" in value or "\n" in value for value in values.values()):
            raise ValueError(f"canary registry entry {index} fields must be single-line strings")
        canary_id = values["canary_id"]
        marker = values["marker"]
        if canary_id in seen_ids:
            raise ValueError(f"duplicate canary_id: {canary_id}")
        if marker in seen_markers:
            raise ValueError(f"duplicate canary marker in entry {index}")
        seen_ids.add(canary_id)
        seen_markers.add(marker)
        canaries.append(CanaryMarker(**values))
    return tuple(canaries)


def canary_registry_agent_root(path: str | Path, agent_roots: Iterable[str | Path]) -> str | None:
    """Return the configured agent root containing the registry, if any."""
    resolved_path = Path(path).expanduser().resolve()
    for root in agent_roots:
        resolved_root = Path(root).expanduser().resolve()
        try:
            resolved_path.relative_to(resolved_root)
        except ValueError:
            continue
        return str(resolved_root)
    return None


def _strings_in(value: Any) -> Iterable[str]:
    """Iterate strings in a JSON-like value without invoking arbitrary reprs."""
    pending = [value]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            yield item
            continue
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend(item.keys())
            pending.extend(item.values())
            continue
        if isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend(item)


def find_canary_matches(
    registry: Sequence[CanaryMarker],
    *,
    content: str | None,
    justification: str,
    parameters: Any,
) -> tuple[CanaryMatch, ...]:
    """Return at most one payload-free observation per registered canary."""
    surfaces = (
        ("content", (content,) if isinstance(content, str) else ()),
        ("justification", (justification,) if isinstance(justification, str) else ()),
        ("parameters", tuple(_strings_in(parameters))),
    )
    matches: list[CanaryMatch] = []
    for canary in registry:
        for where_observed, strings in surfaces:
            if any(canary.marker in value for value in strings):
                matches.append(CanaryMatch(canary.canary_id, where_observed))
                break
    return tuple(matches)
