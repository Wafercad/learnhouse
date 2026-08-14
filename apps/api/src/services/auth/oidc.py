"""Generic OIDC Relying-Party (SP) login for LearnHouse.

LearnHouse federates to an external OpenID Provider — Wafercad's account_service
— so a Wafercad-authenticated user lands in Cloud Campus without a second login.
This is the backend half of the ``auth/sso/*`` contract the frontend already
speaks (``services/auth/sso.ts`` + ``app/auth/sso/callback``).

Flow (authorization code + PKCE S256, single first-party IdP from ``OIDCConfig``):

1. ``build_authorization_url(cfg, org_slug)`` — discover the IdP endpoints, mint
   ``state`` + ``nonce`` + a PKCE verifier/challenge, stash the verifier/nonce/
   org_slug server-side keyed by ``state``, and return the IdP ``/authorize`` URL.
2. IdP authenticates the user and redirects back to the frontend callback with
   ``code`` + ``state``.
3. ``complete_login(cfg, code, state, ...)`` — reload the stashed state, exchange
   the code for tokens at the IdP, validate the ID token (signature via JWKS,
   ``iss``/``aud``/``exp``/``nonce``), JIT-provision the user into the resolved
   org, and mint a LearnHouse session (``purpose: "session"``) token pair.

State/verifier live in Redis when configured; a process-local dict is the dev/test
fallback (a multi-worker deployment must run Redis so both legs share the store).
Identity is keyed on the verified ``email`` claim, normalised to lower-case.
"""

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import urlencode

import httpx
import jwt
from sqlalchemy import func, select
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette.requests import Request

from config.config import OIDCConfig
from src.core.redis import get_redis_client
from src.db.organizations import Organization
from src.db.user_organizations import UserOrganization
from src.db.users import AnonymousUser, User, UserCreate, UserRead
from src.security.auth import create_access_token, create_refresh_token
from src.services.users.users import create_user

# Wafercad role claim -> LearnHouse role_id. Federation is ONE-WAY (Wafercad is
# the IdP), so an LH admin is never a Wafercad admin: a WCS 'instructor' authors
# courses in LH only, and stays an ordinary user in WCS. Unknown/absent roles
# fall back to the configured default (member). LH roles: 1=Admin, 2=Maintainer,
# 4=member.
_LH_ADMIN_ROLE_ID = 1
_LH_MEMBER_ROLE_ID = 4
_ROLE_CLAIM_TO_LH: dict[str, int] = {
    "student": _LH_MEMBER_ROLE_ID,
    "instructor": _LH_ADMIN_ROLE_ID,
    "institution_admin": _LH_ADMIN_ROLE_ID,
    "super_admin": _LH_ADMIN_ROLE_ID,
}

_STATE_PREFIX = "oidc:state:"
_STATE_TTL_SECONDS = 600  # a login round-trip is short; expire dangling state
_HTTP_TIMEOUT_SECONDS = 10.0
_POST_LOGIN_PATH = "/redirect_from_auth"

# Dev/test fallback when Redis is absent. A multi-worker deployment MUST run Redis
# (the authorize and callback legs may hit different workers); documented above.
_MEMORY_STATE: dict[str, str] = {}

# Discovery documents are immutable enough to cache for the process lifetime.
_DISCOVERY_CACHE: dict[str, dict] = {}


class OIDCError(Exception):
    """An OIDC RP failure, carrying an OAuth2-shaped code for the frontend."""

    def __init__(self, error_code: str, description: str) -> None:
        super().__init__(description)
        self.error_code = error_code
        self.description = description

    def to_detail(self) -> dict:
        return {
            "error": self.error_code,
            "error_code": self.error_code,
            "error_description": self.description,
            "provider": "custom_oidc",
        }


# ---------------------------------------------------------------------------
# State store (Redis, with a process-local fallback for dev/test)
# ---------------------------------------------------------------------------
def _store_state(state: str, payload: dict) -> None:
    data = json.dumps(payload)
    client = get_redis_client()
    if client is not None:
        client.set(_STATE_PREFIX + state, data, ex=_STATE_TTL_SECONDS)
    else:
        _MEMORY_STATE[state] = data


def _pop_state(state: str) -> Optional[dict]:
    client = get_redis_client()
    if client is not None:
        key = _STATE_PREFIX + state
        raw = client.get(key)
        if raw is not None:
            client.delete(key)  # single-use: consume on read
        return json.loads(raw) if raw else None
    raw = _MEMORY_STATE.pop(state, None)
    return json.loads(raw) if raw else None


# ---------------------------------------------------------------------------
# Discovery + PKCE
# ---------------------------------------------------------------------------
async def _discover(issuer: str) -> dict:
    cached = _DISCOVERY_CACHE.get(issuer)
    if cached is not None:
        return cached
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
            response = await client.get(url)
            response.raise_for_status()
            document = response.json()
    except httpx.HTTPError as exc:
        raise OIDCError("discovery_failed", f"Could not reach the identity provider: {exc}")
    _DISCOVERY_CACHE[issuer] = document
    return document


def _new_pkce_pair() -> Tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
async def build_authorization_url(cfg: OIDCConfig, org_slug: str) -> Tuple[str, str]:
    """Return (authorization_url, state) to send the browser to the IdP."""
    document = await _discover(cfg.issuer)
    authorization_endpoint = document.get("authorization_endpoint")
    if not authorization_endpoint:
        raise OIDCError("discovery_failed", "IdP discovery is missing authorization_endpoint")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = _new_pkce_pair()
    _store_state(state, {"verifier": verifier, "nonce": nonce, "org_slug": org_slug})

    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": cfg.scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{authorization_endpoint}?{urlencode(params)}", state


async def complete_login(
    cfg: OIDCConfig,
    code: str,
    state: str,
    request: Request,
    db_session: AsyncSession,
) -> Tuple[UserRead, dict, str]:
    """Exchange the code, validate the ID token, JIT-provision, mint a session."""
    stashed = _pop_state(state)
    if stashed is None:
        raise OIDCError("invalid_state", "Unknown or expired login state; please retry.")

    document = await _discover(cfg.issuer)
    token_response = await _exchange_code(cfg, document, code, stashed["verifier"])
    id_token = token_response.get("id_token")
    if not id_token:
        raise OIDCError("no_id_token", "The identity provider did not return an ID token.")

    claims = _validate_id_token(cfg, document, id_token, stashed.get("nonce"))
    user = await _provision_user(cfg, claims, stashed["org_slug"], request, db_session)

    access_token = create_access_token(data={"sub": user.email, "purpose": "session"})
    refresh_token = create_refresh_token(data={"sub": user.email, "purpose": "session"})
    tokens = {"access_token": access_token, "refresh_token": refresh_token, "expiry": None}
    return user, tokens, _POST_LOGIN_PATH


# ---------------------------------------------------------------------------
# Token exchange + ID-token validation
# ---------------------------------------------------------------------------
async def _exchange_code(cfg: OIDCConfig, document: dict, code: str, verifier: str) -> dict:
    token_endpoint = document.get("token_endpoint")
    if not token_endpoint:
        raise OIDCError("discovery_failed", "IdP discovery is missing token_endpoint")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg.redirect_uri,
        "client_id": cfg.client_id,
        "code_verifier": verifier,
    }
    if cfg.client_secret:
        data["client_secret"] = cfg.client_secret
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
            response = await client.post(token_endpoint, data=data)
    except httpx.HTTPError as exc:
        raise OIDCError("token_exchange_failed", f"Token exchange request failed: {exc}")
    if response.status_code != 200:
        raise OIDCError("token_exchange_failed", "The identity provider rejected the authorization code.")
    return response.json()


def _validate_id_token(
    cfg: OIDCConfig,
    document: dict,
    id_token: str,
    expected_nonce: Optional[str],
) -> dict:
    jwks_uri = document.get("jwks_uri")
    if not jwks_uri:
        raise OIDCError("discovery_failed", "IdP discovery is missing jwks_uri")
    expected_issuer = document.get("issuer", cfg.issuer)
    try:
        # PyJWKClient fetches the JWKS with urllib, whose default
        # ``Python-urllib/x.y`` User-Agent is blocked (HTTP 403) by CDN/WAF bot
        # protection (e.g. Cloudflare) that commonly fronts the IdP — the token
        # and discovery calls use httpx and pass, so only this fetch fails. Send
        # an explicit non-bot UA so the back-channel JWKS lookup is not challenged.
        jwks_client = jwt.PyJWKClient(
            jwks_uri, headers={"User-Agent": "learnhouse-oidc-rp/1.0"}
        )
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=cfg.client_id,
            issuer=expected_issuer,
        )
    except jwt.PyJWTError as exc:
        raise OIDCError("invalid_id_token", f"ID token validation failed: {exc}")
    if expected_nonce and claims.get("nonce") != expected_nonce:
        raise OIDCError("nonce_mismatch", "ID token nonce did not match the login request.")
    return claims


# ---------------------------------------------------------------------------
# JIT provisioning (identity keyed on the verified email claim)
# ---------------------------------------------------------------------------
async def _provision_user(
    cfg: OIDCConfig,
    claims: dict,
    org_slug: str,
    request: Request,
    db_session: AsyncSession,
) -> UserRead:
    email = str(claims.get("email") or "").strip().lower()
    if not email:
        raise OIDCError("no_email", "The identity provider returned no email claim.")

    org = (
        await db_session.execute(select(Organization).where(Organization.slug == org_slug))
    ).scalars().first()
    if org is None:
        raise OIDCError("unknown_org", f"No Cloud Campus organization for '{org_slug}'.")

    given_name, family_name = _split_name(claims)
    role_id = _role_id_for(claims.get("role"), cfg)
    existing = (
        await db_session.execute(select(User).where(func.lower(User.email) == email))
    ).scalars().first()

    if existing is None:
        user_object = UserCreate(
            email=email,
            username=_username_for(email),
            password="",
            first_name=given_name,
            last_name=family_name,
        )
        # create_user provisions the user + a role_id=4 membership + marks the
        # OAuth user email-verified. Then align the membership to the mapped role
        # (a no-op for members; elevates instructors/admins).
        created = await create_user(
            request,
            db_session,
            AnonymousUser(),
            user_object,
            org.id,
            is_oauth=True,
            signup_provider="oidc",
        )
        await _apply_membership(getattr(created, "id", None), org.id, role_id, db_session)
        return created

    await _apply_membership(existing.id, org.id, role_id, db_session)
    return UserRead.model_validate(existing)


def _role_id_for(claim_role: object, cfg: OIDCConfig) -> int:
    """Map the Wafercad role claim to a LearnHouse role_id (see _ROLE_CLAIM_TO_LH)."""
    if not claim_role:
        return cfg.default_role_id
    return _ROLE_CLAIM_TO_LH.get(str(claim_role).strip().lower(), cfg.default_role_id)


async def _apply_membership(
    user_id: Optional[int],
    org_id: int,
    role_id: int,
    db_session: AsyncSession,
) -> None:
    """Ensure the user's org membership exists AND carries the mapped role.

    Idempotent, and it re-syncs the role on every login so a Wafercad role change
    propagates to LearnHouse (fresh claims win — design §5.1)."""
    if user_id is None:
        return
    membership = (
        await db_session.execute(
            select(UserOrganization).where(
                (UserOrganization.user_id == user_id)
                & (UserOrganization.org_id == org_id)
            )
        )
    ).scalars().first()
    now = str(datetime.now(timezone.utc))
    if membership is None:
        db_session.add(
            UserOrganization(
                user_id=user_id,
                org_id=org_id,
                role_id=role_id,
                creation_date=now,
                update_date=now,
            )
        )
        await db_session.commit()
        return
    if int(membership.role_id) != role_id:
        membership.role_id = role_id
        membership.update_date = now
        db_session.add(membership)
        await db_session.commit()


def _split_name(claims: dict) -> Tuple[str, str]:
    given = str(claims.get("given_name") or "").strip()
    family = str(claims.get("family_name") or "").strip()
    if given or family:
        return given, family
    full = str(claims.get("name") or "").strip()
    if not full:
        return "", ""
    parts = full.split(" ", 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def _username_for(email: str) -> str:
    """A globally-unique LearnHouse username derived from the email local-part.

    LearnHouse requires a unique username; SSO users never choose one, so we
    derive a stable-ish handle and append entropy to avoid create collisions.
    """
    local = email.split("@", 1)[0]
    cleaned = "".join(ch for ch in local if ch.isalnum()) or "user"
    return f"{cleaned}{secrets.randbelow(900000) + 100000}"
