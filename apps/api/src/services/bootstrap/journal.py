"""Transactional owning-service receipt closes the commit/controller-ack gap."""

from sqlalchemy import text

from .protocol import Conflict, digest

DDL = """
CREATE SCHEMA IF NOT EXISTS wc_bootstrap_owner;
CREATE TABLE IF NOT EXISTS wc_bootstrap_owner.applied (
 task text NOT NULL, scope text NOT NULL, version integer NOT NULL,
 checksum text NOT NULL, receipt jsonb NOT NULL,
 applied_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (task, scope)
)
"""


def dispatch(session, request, execute):
    """Run under the caller's transaction and lock; never commit independently."""
    import json

    postgres = session.bind.dialect.name == "postgresql"
    table = (
        postgres
        and session.execute(text("SELECT to_regclass('wc_bootstrap_owner.applied')")).scalar()
    )
    prior = None
    params = {"task": request["task"], "scope": request["scope"]}
    if table:
        prior = (
            session.execute(
                text(
                    "SELECT version, checksum, receipt FROM wc_bootstrap_owner.applied "
                    "WHERE task=:task AND scope=:scope"
                ),
                params,
            )
            .mappings()
            .one_or_none()
        )
    if prior:
        if prior["version"] > request["version"]:
            raise Conflict("owner_version_downgrade")
        # The owner's receipt committed with its writes and is stronger evidence
        # than an interrupted controller's earlier partial snapshot.
        request = {**request, "receipt": prior["receipt"]}
    response = execute(request)
    if response["status"] in {"conflict", "blocked"}:
        return response
    checksum = digest(
        [
            request["task"],
            request["scope"],
            request["version"],
            request["data"],
            response["definition"],
        ]
    )
    if prior and prior["version"] == request["version"] and prior["checksum"] != checksum:
        raise Conflict("owner_changed_without_version")
    if request["action"] == "apply" and response["status"] == "ready" and postgres:
        if not table:
            session.execute(text(DDL))
        session.execute(
            text(
                "INSERT INTO wc_bootstrap_owner.applied (task,scope,version,checksum,receipt) "
                "VALUES (:task,:scope,:version,:checksum,CAST(:receipt AS jsonb)) "
                "ON CONFLICT (task,scope) DO UPDATE SET version=EXCLUDED.version, "
                "checksum=EXCLUDED.checksum,receipt=EXCLUDED.receipt,applied_at=now()"
            ),
            {
                **params,
                "version": request["version"],
                "checksum": checksum,
                "receipt": json.dumps(response["receipt"]),
            },
        )
    return response
