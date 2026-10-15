"""Policy file loader.

`load_policy` either returns a fully validated `Policy` stamped with the sha256 of the file bytes,
or raises `PolicyError`. Callers treat `PolicyError` as DENY (fail closed). Error messages name the
path and the kind of failure only, never file contents (AGENTS.md §2.2). The PolicyError is raised
outside any `except` block so the original error, which can quote the file, is not even attached
as `__context__`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Hashable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

from firewall.errors import PolicyError
from firewall.models import Policy

# A real policy is about 2 KB. The cap bounds parse time and memory before YAML sees the bytes.
MAX_POLICY_BYTES = 64_000


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys. By default a later key silently overrides an
    earlier one, so a reviewer could approve `mode: enforce` while `mode: shadow` takes effect."""

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Hashable, Any]:
        seen: set[Hashable] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            # Unhashable keys are left to the base class, which rejects them.
            if isinstance(key, Hashable):
                if key in seen:
                    raise ConstructorError(problem="duplicate mapping key")
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


# Public name for other loaders of human-reviewed YAML (eval/run_eval.py thresholds).
UniqueKeyLoader = _UniqueKeyLoader


def _try_load(path: Path) -> Policy | str:
    """Return the validated policy, or a short failure kind that contains no file content."""
    try:
        raw = path.read_bytes()
    except OSError:
        return "unreadable"
    if len(raw) > MAX_POLICY_BYTES:
        return "too large"
    try:
        data = yaml.load(raw, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except (yaml.YAMLError, RecursionError):
        return "not valid YAML"
    if not isinstance(data, dict):
        return "not a mapping"
    # The hash is computed from the bytes, never declared: a declared one could lie.
    if "sha256" in data:
        return "declares sha256"
    try:
        return Policy.model_validate({**data, "sha256": hashlib.sha256(raw).hexdigest()})
    except ValidationError:
        return "failed validation"


def load_policy(path: Path) -> Policy:
    result = _try_load(path)
    if isinstance(result, str):
        raise PolicyError(f"policy file rejected ({result}): {path}")
    return result
