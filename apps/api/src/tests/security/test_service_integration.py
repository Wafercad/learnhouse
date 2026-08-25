"""Wafercad service-integration token — the security invariants (fork spec §5).

Unit-tests the two dependencies by patching the auth seam (`get_authenticated_user`,
lazily imported by the module) to inject a chosen principal, and toggling the
feature flag via `_feature_enabled`. The real user/org rows come from the shared
conftest fixtures (in-memory SQLite).
"""

import pytest
from fastapi import HTTPException

import src.security.auth as auth
from src.db.users import APITokenUser
from src.security import service_integration as si


class _URL:
    def __init__(self, path: str) -> None:
        self.path = path


class _Client:
    host = "1.2.3.4"


class _Req:
    def __init__(self, headers=None, method="POST", path="/api/v1/trail/x"):
        self.headers = headers or {}
        self.method = method
        self.url = _URL(path)
        self.client = _Client()


def _service_token(org_id=1):
    return APITokenUser(
        id=1,
        user_uuid="apitoken_svc",
        username="api_token",
        org_id=org_id,
        token_name="campus",
        created_by_user_id=1,
        is_service_integration=True,
    )


def _plain_token(org_id=1):
    return APITokenUser(id=2, org_id=org_id, token_name="plain", created_by_user_id=1)


def _patch_principal(monkeypatch, principal):
    async def _fake(request, db_session):
        return principal

    monkeypatch.setattr(auth, "get_authenticated_user", _fake)


def _capture(calls):
    async def _rec(**kwargs):
        calls.append(kwargs)

    return _rec


@pytest.fixture(autouse=True)
def _feature_on(monkeypatch):
    monkeypatch.setattr(si, "_feature_enabled", lambda: True)


# --- resolve_effective_user ------------------------------------------------
async def test_header_on_non_service_token_is_403(db, monkeypatch):
    _patch_principal(monkeypatch, _plain_token())
    req = _Req(headers={si.ON_BEHALF_HEADER: "apitoken_target"})
    with pytest.raises(HTTPException) as err:
        await si.resolve_effective_user(req, db)
    assert err.value.status_code == 403


async def test_header_absent_session_user_is_unchanged(db, monkeypatch, admin_user):
    _patch_principal(monkeypatch, admin_user)
    result = await si.resolve_effective_user(_Req(headers={}), db)
    assert result is admin_user


async def test_service_token_without_header_is_400(db, monkeypatch):
    _patch_principal(monkeypatch, _service_token())
    with pytest.raises(HTTPException) as err:
        await si.resolve_effective_user(_Req(headers={}), db)
    assert err.value.status_code == 400


async def test_on_behalf_resolves_learner_and_audits(db, monkeypatch, admin_user):
    calls = []
    monkeypatch.setattr(si, "record_audit_event", _capture(calls))
    _patch_principal(monkeypatch, _service_token(org_id=1))
    req = _Req(headers={si.ON_BEHALF_HEADER: admin_user.user_uuid})
    result = await si.resolve_effective_user(req, db)
    assert result.user_uuid == admin_user.user_uuid
    assert not isinstance(result, APITokenUser)  # a normal learner principal
    assert len(calls) == 1
    assert calls[0]["metadata"]["actor"] == "service_token"


async def test_on_behalf_cross_org_is_403(db, monkeypatch, admin_user):
    monkeypatch.setattr(si, "record_audit_event", _capture([]))
    _patch_principal(monkeypatch, _service_token(org_id=2))  # target is in org 1
    req = _Req(headers={si.ON_BEHALF_HEADER: admin_user.user_uuid})
    with pytest.raises(HTTPException) as err:
        await si.resolve_effective_user(req, db)
    assert err.value.status_code == 403


async def test_on_behalf_unknown_user_is_404(db, monkeypatch):
    _patch_principal(monkeypatch, _service_token())
    req = _Req(headers={si.ON_BEHALF_HEADER: "nope_uuid"})
    with pytest.raises(HTTPException) as err:
        await si.resolve_effective_user(req, db)
    assert err.value.status_code == 404


async def test_feature_off_rejects_on_behalf(db, monkeypatch):
    monkeypatch.setattr(si, "_feature_enabled", lambda: False)
    _patch_principal(monkeypatch, _service_token())
    req = _Req(headers={si.ON_BEHALF_HEADER: "x"})
    with pytest.raises(HTTPException) as err:
        await si.resolve_effective_user(req, db)
    assert err.value.status_code == 403


# --- require_trail_principal (router gate) ---------------------------------
async def test_gate_blocks_api_token_when_feature_off(db, monkeypatch):
    monkeypatch.setattr(si, "_feature_enabled", lambda: False)
    _patch_principal(monkeypatch, _service_token())
    with pytest.raises(HTTPException) as err:
        await si.require_trail_principal(_Req(), db)
    assert err.value.status_code == 403


async def test_gate_admits_service_token_when_feature_on(db, monkeypatch):
    _patch_principal(monkeypatch, _service_token())
    result = await si.require_trail_principal(_Req(), db)
    assert isinstance(result, APITokenUser)


async def test_gate_admits_session_user(db, monkeypatch, admin_user):
    _patch_principal(monkeypatch, admin_user)
    result = await si.require_trail_principal(_Req(), db)
    assert result is admin_user
