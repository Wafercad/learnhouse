"""Wafercad bootstrap protocol v1 (LearnHouse has no EDA Python dependency)."""

import hashlib
import json


class Conflict(Exception):
    """Sanitized machine-readable conflict."""


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def result(status, definition, receipt=None, code="ok"):
    return dict(protocol=1, status=status, definition=definition, receipt=receipt or {}, code=code)


def dependency(request, field):
    name = request["data"].get(field)
    value = request.get("dependencies", {}).get(name)
    if not value:
        raise Conflict("verified_dependency_required")
    return value
