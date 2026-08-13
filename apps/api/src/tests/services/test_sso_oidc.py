"""OIDC Relying-Party login — service + router unit/integration tests.

Real in-memory DB (conftest fixtures) for the provisioning branches; the network
legs (discovery, token exchange, ID-token validation) are mocked so the tests are
deterministic and offline. Covers the PKCE authorize URL, the end-to-end callback
wiring, JIT provisioning (new + idempotent existing membership), the nonce guard,
and the claim/state/org validation failures.
"""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from sqlmodel import select
from starlette.requests import Request

from config.config import OIDCConfig
from src.db.user_organizations import UserOrganization
from src.db.users import User
from src.routers import sso as sso_router
from src.services.auth import oidc

_MODULE = "src.services.auth.oidc"


def _cfg() -> OIDCConfig:
    return OIDCConfig(
        issuer="https://idp.test",
        client_id="cloud-campus",
        client_secret=None,
        redirect_uri="https://campus.test/auth/sso/callback",
        scopes="openid email profile",
        default_role_id=4,
        provider="custom_oidc",
    )


_DISCOVERY = {
    "issuer": "https://idp.test",
    "authorization_endpoint": "https://idp.test/oauth/authorize",
    "token_endpoint": "https://idp.test/oauth/token",
    "jwks_uri": "https://idp.test/oauth/jwks",
    "userinfo_endpoint": "https://idp.test/oauth/userinfo",
}


@pytest.fixture
def mock_request():
    r = Mock(spec=Request)
    r.client = SimpleNamespace(host="10.0.0.9")
    return r


# ---------------------------------------------------------------------------
# authorize URL + PKCE/state
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_build_authorization_url_stashes_state_and_carries_pkce():
    with patch(f"{_MODULE}._discover", new=AsyncMock(return_value=_DISCOVERY)):
        url, state = await oidc.build_authorization_url(_cfg(), "wc-academy")

    assert url.startswith("https://idp.test/oauth/authorize?")
    assert "client_id=cloud-campus" in url
    assert "code_challenge_method=S256" in url
    assert "code_challenge=" in url
    assert f"state={state}" in url
    # the verifier/nonce/org are stashed for the callback leg
    stashed = oidc._pop_state(state)
    assert stashed is not None
    assert stashed["org_slug"] == "wc-academy"
    assert stashed["verifier"] and stashed["nonce"]


# ---------------------------------------------------------------------------
# callback wiring
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_complete_login_wires_exchange_validate_provision_and_mints_session(
    mock_request,
):
    oidc._store_state("st-1", {"verifier": "v", "nonce": "n", "org_slug": "wc-academy"})
    user = SimpleNamespace(email="learner@x.com")
    with patch(f"{_MODULE}._discover", new=AsyncMock(return_value=_DISCOVERY)), patch(
        f"{_MODULE}._exchange_code",
        new=AsyncMock(return_value={"id_token": "id.jwt"}),
    ), patch(
        f"{_MODULE}._validate_id_token",
        return_value={"email": "learner@x.com", "sub": "usr_1", "nonce": "n"},
    ), patch(
        f"{_MODULE}._provision_user", new=AsyncMock(return_value=user)
    ) as provision:
        result_user, tokens, redirect_url = await oidc.complete_login(
            _cfg(), "code-xyz", "st-1", mock_request, db_session=Mock()
        )

    assert result_user is user
    assert tokens["access_token"] and tokens["refresh_token"]
    assert tokens["expiry"] is None
    assert redirect_url == oidc._POST_LOGIN_PATH
    provision.assert_awaited_once()
    # state was consumed — a replay finds nothing
    assert oidc._pop_state("st-1") is None


@pytest.mark.asyncio
async def test_complete_login_rejects_unknown_state(mock_request):
    with pytest.raises(oidc.OIDCError) as exc:
        await oidc.complete_login(
            _cfg(), "code", "never-issued", mock_request, db_session=Mock()
        )
    assert exc.value.error_code == "invalid_state"


# ---------------------------------------------------------------------------
# JIT provisioning
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_provision_new_user_calls_create_user_with_normalized_identity(
    db, org, user_role, mock_request
):
    created = SimpleNamespace(email="learner@x.com")
    with patch(
        f"{_MODULE}.create_user", new=AsyncMock(return_value=created)
    ) as create:
        result = await oidc._provision_user(
            _cfg(),
            {
                "email": "Learner@X.com",  # mixed case — must normalise
                "sub": "usr_1",
                "given_name": "Pat",
                "family_name": "Prospect",
            },
            org.slug,
            mock_request,
            db,
        )

    assert result is created
    create.assert_awaited_once()
    user_object = create.call_args.args[3]
    passed_org_id = create.call_args.args[4]
    assert passed_org_id == org.id
    assert user_object.email == "learner@x.com"
    assert user_object.first_name == "Pat"
    assert user_object.last_name == "Prospect"
    assert user_object.username.startswith("learner")
    assert create.call_args.kwargs["signup_provider"] == "oidc"


@pytest.mark.asyncio
async def test_provision_existing_user_adds_membership_exactly_once(
    db, org, user_role, mock_request
):
    db.add(
        User(
            id=50,
            username="dup",
            first_name="Dup",
            last_name="User",
            email="dup@x.com",
            password="",
            user_uuid="user_dup",
            creation_date=str(datetime.now()),
            update_date=str(datetime.now()),
        )
    )
    await db.commit()

    claims = {"email": "Dup@X.com", "sub": "s"}  # existing user, mixed case
    await oidc._provision_user(_cfg(), claims, org.slug, mock_request, db)
    await oidc._provision_user(_cfg(), claims, org.slug, mock_request, db)

    memberships = (
        await db.execute(
            select(UserOrganization).where(
                (UserOrganization.user_id == 50) & (UserOrganization.org_id == org.id)
            )
        )
    ).scalars().all()
    assert len(memberships) == 1
    assert memberships[0].role_id == 4


@pytest.mark.asyncio
async def test_provision_rejects_missing_email(db, org, mock_request):
    with pytest.raises(oidc.OIDCError) as exc:
        await oidc._provision_user(_cfg(), {"sub": "s"}, org.slug, mock_request, db)
    assert exc.value.error_code == "no_email"


@pytest.mark.asyncio
async def test_provision_rejects_unknown_org(db, mock_request):
    with pytest.raises(oidc.OIDCError) as exc:
        await oidc._provision_user(
            _cfg(), {"email": "a@b.com"}, "no-such-org", mock_request, db
        )
    assert exc.value.error_code == "unknown_org"


# ---------------------------------------------------------------------------
# ID-token validation (nonce guard)
# ---------------------------------------------------------------------------
def test_validate_id_token_rejects_nonce_mismatch():
    fake_jwk = MagicMock()
    fake_jwk.get_signing_key_from_jwt.return_value = SimpleNamespace(key="k")
    with patch(f"{_MODULE}.jwt.PyJWKClient", return_value=fake_jwk), patch(
        f"{_MODULE}.jwt.decode", return_value={"nonce": "attacker"}
    ):
        with pytest.raises(oidc.OIDCError) as exc:
            oidc._validate_id_token(_cfg(), _DISCOVERY, "id.jwt", expected_nonce="mine")
    assert exc.value.error_code == "nonce_mismatch"


# ---------------------------------------------------------------------------
# router: /check
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sso_check_reports_enabled_when_configured():
    with patch.object(
        sso_router,
        "get_learnhouse_config",
        return_value=SimpleNamespace(oidc_config=_cfg()),
    ):
        assert await sso_router.sso_check("wc-academy") == {
            "sso_enabled": True,
            "provider": "custom_oidc",
        }


@pytest.mark.asyncio
async def test_sso_check_reports_disabled_when_unconfigured():
    with patch.object(
        sso_router,
        "get_learnhouse_config",
        return_value=SimpleNamespace(oidc_config=None),
    ):
        assert await sso_router.sso_check("wc-academy") == {
            "sso_enabled": False,
            "provider": None,
        }
