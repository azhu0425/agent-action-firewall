"""Policy file loader.

`load_policy` either returns a fully validated `Policy` stamped with the sha256 of the file bytes,
or raises `PolicyError`. Callers treat `PolicyError` as DENY (fail closed). Error messages name the
path and the kind of failure only, never file contents (AGENTS.md §2.2), so causes are suppressed:
a chained YAML or validation error would carry the offending values.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import ValidationError

from firewall.errors import PolicyError
from firewall.models import Policy


def load_policy(path: Path) -> Policy:
    try:
        raw = path.read_bytes()
    except OSError:
        raise PolicyError(f"policy file unreadable: {path}") from None

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError:
        raise PolicyError(f"policy file is not valid YAML: {path}") from None

    if not isinstance(data, dict):
        raise PolicyError(f"policy file is not a mapping: {path}")
    # The hash is computed from the bytes, never declared: a declared one could lie.
    if "sha256" in data:
        raise PolicyError(f"policy file must not declare sha256: {path}")

    try:
        return Policy.model_validate({**data, "sha256": hashlib.sha256(raw).hexdigest()})
    except ValidationError:
        raise PolicyError(f"policy file failed validation: {path}") from None
