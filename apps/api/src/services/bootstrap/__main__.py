"""A bounded transactional command for Docker or a future Kubernetes Job."""

from contextlib import redirect_stdout
import json
import os
import sys

from sqlalchemy import create_engine, text
from sqlmodel import Session

from .protocol import Conflict, digest, result
from .journal import dispatch


def handle(request):
    if (
        request.get("protocol") != 1
        or request.get("action") not in {"verify", "apply"}
        or request.get("environment") not in {"local", "stage", "prod", "production"}
        or request["environment"] != os.environ.get("WC_DEPLOYMENT_ENVIRONMENT")
    ):
        raise Conflict("invalid_environment_or_request")
    task = request.get("task")
    from . import foundation, curriculum, content, course_pack

    owners = {
        "learnhouse-foundation": foundation,
        "learnhouse-curriculum": curriculum,
        "learnhouse-content": content,
        "learnhouse-course-pack": course_pack,
    }
    if task not in owners:
        raise Conflict("unknown_learnhouse_task")
    # All calls are against this service's configured database, not a request URL.
    url = os.environ["LEARNHOUSE_SQL_CONNECTION_STRING"].replace(
        "+asyncpg", "+psycopg2"
    )
    engine = create_engine(
        url,
        hide_parameters=True,
        pool_pre_ping=True,
        connect_args={"connect_timeout": 10},
    )
    try:
        with Session(engine) as session, session.begin():
            if request["action"] == "verify":
                session.execute(text("SET TRANSACTION READ ONLY"))
            else:
                session.execute(text("SET LOCAL lock_timeout = '5s'"))
                # Serialize all bootstrap resources in this owning database.
                session.execute(text("SELECT pg_advisory_xact_lock(627894531)"))
            expected = request.get("database_target", {})
            actual = session.execute(
                text("SELECT current_database(), inet_server_addr()::text")
            ).one()
            if actual[0] != expected.get("database") or actual[1] not in expected.get(
                "addresses", []
            ):
                raise Conflict("database_target_mismatch")
            response = dispatch(
                session,
                request,
                lambda operation: owners[task].execute(session, operation),
            )
            if request["action"] == "apply" and response["status"] != "ready":
                raise Conflict(response["code"])
            return response
    finally:
        engine.dispose()


def main():
    try:
        raw = sys.stdin.buffer.read(512 * 1024 + 1)
        if len(raw) > 512 * 1024:
            raise Conflict("input_too_large")
        with redirect_stdout(sys.stderr):
            response = handle(json.loads(raw))
    except Conflict as error:
        code = str(error)
        if not code.replace("_", "").isalnum() or len(code) > 80:
            code = "existing_data_conflict"
        response = result("conflict", digest("unavailable"), code=code)
    except Exception:
        response = result(
            "blocked", digest("unavailable"), code="service_prerequisite_failed"
        )
    print(json.dumps(response))


if __name__ == "__main__":
    main()
