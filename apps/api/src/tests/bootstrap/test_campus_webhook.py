"""The Campus webhook endpoint is bootstrap-owned: created once, verified after."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlmodel import Session, SQLModel, select

from src.db.api_tokens import APIToken
from src.db.organization_config import OrganizationConfig
from src.db.organizations import Organization
from src.db.roles import Role
from src.db.user_organizations import UserOrganization
from src.db.users import User
from src.db.webhooks import WebhookEndpoint
from src.services.bootstrap import campus_webhook, foundation
from src.services.bootstrap.protocol import Conflict
from src.services.webhooks.crypto import decrypt_secret

# A private literal, so the real SSRF guard decides without DNS.
URL = "http://10.20.30.40:8010/campus/api/v1/webhooks/learnhouse"
SECRET = "s" * 64


@compiles(JSONB, "sqlite")
def jsonb_sqlite(*args, **kwargs):
    return "JSON"


@pytest.fixture
def session(monkeypatch):
    monkeypatch.setenv("LEARNHOUSE_WEBHOOK_ALLOWED_PRIVATE_HOSTS", "10.20.30.40")
    engine = create_engine("sqlite://")
    models = (
        Organization, User, Role, APIToken, UserOrganization, OrganizationConfig,
        WebhookEndpoint,
    )
    SQLModel.metadata.create_all(engine, tables=[m.__table__ for m in models])
    with Session(engine) as session:
        yield session
    engine.dispose()


def academy(session):
    output = foundation.execute(
        session,
        dict(
            action="apply",
            scope="academy:test",
            receipt={},
            data=dict(
                slug="test-academy",
                name="Test Academy",
                admin_email="admin@example.org",
                admin_username="test-operator",
                password_env="ADMIN_PASSWORD",
                service_key_env="CAMPUS_KEY",
            ),
            secrets={"ADMIN_PASSWORD": "Disposable-Password-456", "CAMPUS_KEY": "lh_" + "a" * 43},
        ),
    )
    assert output["status"] == "ready"
    return output["receipt"]


def webhook(receipt, action="apply", **overrides):
    data = dict(
        foundation_step="foundation",
        url=URL,
        events=["course_published", "course_created", "course_deleted"],
        secret_env="CAMPUS_SECRET",
    )
    return dict(
        action=action,
        scope="academy:test:campus-webhook",
        receipt={},
        data={**data, **overrides},
        dependencies={"foundation": receipt},
        secrets={"CAMPUS_SECRET": SECRET},
    )


def test_verify_writes_nothing_then_apply_registers_once(session):
    receipt = academy(session)
    assert campus_webhook.execute(session, webhook(receipt, "verify"))["status"] == "missing"
    assert not session.exec(select(WebhookEndpoint)).all()

    first = campus_webhook.execute(session, webhook(receipt))
    again = campus_webhook.execute(session, webhook(receipt))
    assert first["status"] == again["status"] == "ready"
    assert first["receipt"] == again["receipt"]
    endpoint = session.exec(select(WebhookEndpoint)).one()
    assert endpoint.org_id == receipt["org_id"]
    assert endpoint.created_by_user_id == receipt["admin_id"]
    assert endpoint.is_active and endpoint.url == URL
    assert endpoint.events == ["course_created", "course_deleted", "course_published"]
    # Stored the way LearnHouse stores its own, and signs with Campus's secret.
    assert endpoint.secret_encrypted != SECRET
    assert decrypt_secret(endpoint.secret_encrypted) == SECRET


def test_a_lost_endpoint_is_recreated(session):
    receipt = academy(session)
    first = campus_webhook.execute(session, webhook(receipt))
    session.delete(session.exec(select(WebhookEndpoint)).one())
    session.flush()
    request = webhook(receipt)
    request["receipt"] = first["receipt"]
    assert campus_webhook.execute(session, request)["status"] == "ready"
    assert len(session.exec(select(WebhookEndpoint)).all()) == 1


def test_a_destination_delivery_would_refuse_is_not_registered(session, monkeypatch):
    monkeypatch.delenv("LEARNHOUSE_WEBHOOK_ALLOWED_PRIVATE_HOSTS")
    receipt = academy(session)
    with pytest.raises(Conflict, match="campus_webhook_destination_refused"):
        campus_webhook.execute(session, webhook(receipt))
    assert not session.exec(select(WebhookEndpoint)).all()


@pytest.mark.parametrize(
    "drift, code",
    [
        ("disabled", "campus_webhook_disabled"),
        ("events", "campus_webhook_events_changed"),
        ("secret", "campus_webhook_secret_mismatch"),
    ],
)
def test_drift_is_a_conflict_not_an_overwrite(session, drift, code):
    receipt = academy(session)
    campus_webhook.execute(session, webhook(receipt))
    endpoint = session.exec(select(WebhookEndpoint)).one()
    request = webhook(receipt)
    if drift == "disabled":
        endpoint.is_active = False
    elif drift == "events":
        endpoint.events = ["course_published"]
    else:
        request["secrets"]["CAMPUS_SECRET"] = "r" * 64
    session.flush()
    with pytest.raises(Conflict, match=code):
        campus_webhook.execute(session, request)


@pytest.mark.parametrize(
    "overrides, secret, code",
    [
        ({"events": ["course_publish"]}, SECRET, "invalid_campus_webhook_events"),
        ({"url": "ftp://campus/hook"}, SECRET, "invalid_campus_webhook_url"),
        ({}, "short", "campus_webhook_secret_required"),
    ],
)
def test_bad_specs_are_refused(session, overrides, secret, code):
    request = webhook(academy(session), **overrides)
    request["secrets"]["CAMPUS_SECRET"] = secret
    with pytest.raises(Conflict, match=code):
        campus_webhook.execute(session, request)
