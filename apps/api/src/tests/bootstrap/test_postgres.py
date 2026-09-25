"""Opt-in PostgreSQL test of the actual owner command and atomic receipts."""

import os
import uuid
from copy import deepcopy

import pytest
from sqlalchemy import create_engine, text
from sqlmodel import Session, SQLModel, select

from src.services.bootstrap.__main__ import handle
from src.services.bootstrap.protocol import Conflict
from src.db.courses.assignments import Assignment, AssignmentTask
from src.tests.bootstrap.test_course_pack import pack
from src.tests.bootstrap.test_lifecycle import (
    Organization,
    User,
    Role,
    APIToken,
    UserOrganization,
    OrganizationConfig,
    Course,
    Chapter,
    CourseChapter,
    Activity,
    ChapterActivity,
    ResourceAuthor,
    request,
)


def test_owner_transaction_readonly_identity_and_lost_ack(monkeypatch):
    dsn = os.environ.get("WC_BOOTSTRAP_TEST_DSN")
    if not dsn:
        pytest.skip("requires an explicitly disposable PostgreSQL server")
    import psycopg2
    from psycopg2 import sql
    from sqlalchemy.engine import URL

    admin = psycopg2.connect(dsn)
    admin.autocommit = True
    name = "wc_bootstrap_test_lh_" + uuid.uuid4().hex
    params = admin.get_dsn_parameters()
    url = URL.create(
        "postgresql+psycopg2",
        username=params["user"],
        password=psycopg2.extensions.parse_dsn(dsn).get("password"),
        host=params["host"],
        port=int(params["port"]),
        database=name,
    )
    engine = None
    try:
        with admin.cursor() as cursor:
            cursor.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        engine = create_engine(url)
        models = (
            Organization,
            User,
            Role,
            APIToken,
            UserOrganization,
            OrganizationConfig,
            Course,
            Chapter,
            CourseChapter,
            Activity,
            ChapterActivity,
            ResourceAuthor,
            Assignment,
            AssignmentTask,
        )
        SQLModel.metadata.create_all(engine, tables=[m.__table__ for m in models])
        with engine.connect() as connection:
            address = connection.execute(
                text("SELECT inet_server_addr()::text")
            ).scalar()
        monkeypatch.setenv("WC_DEPLOYMENT_ENVIRONMENT", "local")
        monkeypatch.setenv(
            "LEARNHOUSE_SQL_CONNECTION_STRING",
            url.render_as_string(hide_password=False),
        )
        operation = {
            **request(),
            "protocol": 1,
            "version": 1,
            "environment": "local",
            "task": "learnhouse-foundation",
            "action": "verify",
            "database_target": {"database": name, "addresses": [address]},
        }
        assert handle(operation)["status"] == "missing"
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT to_regnamespace('wc_bootstrap_owner')")
                ).scalar()
                is None
            )
        first = handle({**operation, "action": "apply"})
        assert first["status"] == "ready"
        assert handle(operation)["receipt"] == first["receipt"]  # No central ACK.
        learning = {
            **operation,
            "task": "learnhouse-course-pack",
            "scope": "fixture:test-course",
            "data": {"foundation_step": "foundation", "pack": pack()},
            "dependencies": {"foundation": first["receipt"]},
        }
        assert handle(learning)["status"] == "missing"
        invalid = deepcopy(learning)
        invalid["action"] = "apply"
        invalid["data"]["pack"]["course"]["chapters"][0]["activities"][0]["assignment"][
            "tasks"
        ][0]["max_grade_value"] = -1
        with pytest.raises(ValueError):
            handle(invalid)
        with Session(engine) as session:
            assert not session.exec(select(Course)).all()  # Entire import rolled back.
        imported = handle({**learning, "action": "apply"})
        assert imported["status"] == "ready"
        assert handle(learning)["receipt"] == imported["receipt"]
        assert handle({**learning, "action": "apply"})["receipt"] == imported["receipt"]
        with Session(engine) as session:
            assert len(session.exec(select(AssignmentTask)).all()) == 1
            session.exec(select(Activity)).one().published = False
            session.commit()
        with pytest.raises(Conflict, match="unpublished"):
            handle({**learning, "action": "apply"})
        with Session(engine) as session:
            assert (
                session.execute(
                    text("SELECT nextval(pg_get_serial_sequence('role','id'))")
                ).scalar()
                > 5
            )
            session.exec(select(APIToken)).one().is_active = False
            session.commit()
        with pytest.raises(Conflict, match="revoked"):
            handle({**operation, "action": "apply"})
        with pytest.raises(Conflict, match="database_target_mismatch"):
            handle(
                {
                    **operation,
                    "database_target": {"database": "wrong", "addresses": [address]},
                }
            )
    finally:
        if engine:
            engine.dispose()
        with admin.cursor() as cursor:
            cursor.execute(
                sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(name))
            )
        admin.close()
