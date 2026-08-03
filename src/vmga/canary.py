"""Operator-owned canary registry and proposal-surface matching."""

from __future__ import annotations

from dataclasses import dataclass
import os
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
    registry_path = _reject_symlinked_registry_path(path)
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
        canaries.append(CanaryMarker(**values))
    return validate_canary_registry(canaries)


def validate_canary_registry(registry: Sequence[CanaryMarker]) -> tuple[CanaryMarker, ...]:
    canaries = tuple(registry)
    seen_ids: set[str] = set()
    seen_markers: set[str] = set()
    for index, canary in enumerate(canaries):
        if not isinstance(canary, CanaryMarker):
            raise ValueError("canary_registry entries must be CanaryMarker instances")
        values = (canary.canary_id, canary.marker, canary.location_hint)
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError(f"canary registry entry {index} fields must be non-empty strings")
        if any("\x00" in value or "\r" in value or "\n" in value for value in values):
            raise ValueError(f"canary registry entry {index} fields must be single-line strings")
        if canary.canary_id in seen_ids:
            raise ValueError(f"duplicate canary_id: {canary.canary_id}")
        if canary.marker in seen_markers:
            raise ValueError(f"duplicate canary marker in entry {index}")
        seen_ids.add(canary.canary_id)
        seen_markers.add(canary.marker)

    markers = tuple(canary.marker for canary in canaries)
    for canary in canaries:
        if any(marker in canary.canary_id for marker in markers):
            raise ValueError(f"canary_id contains a registered canary marker: {canary.canary_id}")
    return canaries


def canary_registry_agent_root(path: str | Path, agent_roots: Iterable[str | Path]) -> str | None:
    """Return the configured agent root containing the registry, if any."""
    lexical_path = _absolute_lexical_path(path)
    for root in agent_roots:
        lexical_root = _absolute_lexical_path(root)
        try:
            lexical_path.relative_to(lexical_root)
        except ValueError:
            continue
        return str(Path(root).expanduser().resolve())
    _reject_symlinked_registry_path(lexical_path)
    return None


def _absolute_lexical_path(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _contains_symlink(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts:
        if part == path.anchor:
            continue
        current /= part
        if current.is_symlink():
            return True
    return False


def _reject_symlinked_registry_path(path: str | Path) -> Path:
    lexical_path = _absolute_lexical_path(path)
    if _contains_symlink(lexical_path):
        raise ValueError("canary registry path must not contain symlinks")
    return lexical_path


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
