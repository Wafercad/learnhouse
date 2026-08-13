"""SSO (OIDC Relying-Party) login endpoints — the ``auth/sso/*`` login flow.

Public, no-auth endpoints that let a Wafercad-authenticated user reach Cloud
Campus via the external IdP (account_service). The heavy lifting lives in
``src.services.auth.oidc``; these handlers only translate HTTP <-> service and
render OAuth2-shaped errors the frontend (``services/auth/sso.ts``) understands.

- ``GET /auth/sso/check``     — is OIDC enabled? (drives the login-page button)
- ``GET /auth/sso/authorize`` — JSON {authorization_url, state} for the SPA button
- ``GET /auth/sso/start``     — 302 to the IdP for SP-initiated entry (the hub
                                handoff redirects a browser straight here)
- ``GET /auth/sso/callback``  — exchange the code, provision, mint a session
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, RedirectResponse
from sqlmodel.ext.asyncio.session import AsyncSession

from config.config import get_learnhouse_config
from src.core.events.database import get_db_session
from src.routers.auth import set_auth_cookies
from src.services.auth.oidc import (
    OIDCError,
    build_authorization_url,
    complete_login,
)

router = APIRouter()


def _require_oidc():
    cfg = get_learnhouse_config().oidc_config
    if cfg is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "sso_not_configured",
                "error_code": "sso_not_configured",
                "error_description": "OIDC single sign-on is not configured on this instance.",
            },
        )
    return cfg


def _oidc_http_error(exc: OIDCError) -> HTTPException:
    # invalid_state / nonce_mismatch are client-recoverable (retry); everything
    # else is an upstream/config failure. Both render the SSOErrorDetail shape.
    status_code = 400 if exc.error_code in {"invalid_state", "nonce_mismatch"} else 502
    return HTTPException(status_code=status_code, detail=exc.to_detail())


@router.get("/check", summary="Whether OIDC SSO is enabled for an org")
async def sso_check(org_slug: str):
    cfg = get_learnhouse_config().oidc_config
    if cfg is None:
        return {"sso_enabled": False, "provider": None}
    return {"sso_enabled": True, "provider": cfg.provider}


@router.get("/authorize", summary="Begin OIDC login (returns the IdP URL as JSON)")
async def sso_authorize(org_slug: str):
    cfg = _require_oidc()
    try:
        authorization_url, state = await build_authorization_url(cfg, org_slug)
    except OIDCError as exc:
        raise _oidc_http_error(exc)
    return {"authorization_url": authorization_url, "state": state}


@router.get("/start", summary="Begin OIDC login (302 to the IdP — SP-initiated)")
async def sso_start(org_slug: str):
    cfg = _require_oidc()
    try:
        authorization_url, _state = await build_authorization_url(cfg, org_slug)
    except OIDCError as exc:
        raise _oidc_http_error(exc)
    return RedirectResponse(url=authorization_url, status_code=302)


@router.get("/callback", summary="Complete OIDC login (exchange code, mint session)")
async def sso_callback(
    code: str,
    state: str,
    request: Request,
    db_session: AsyncSession = Depends(get_db_session),
):
    cfg = _require_oidc()
    try:
        user, tokens, redirect_url = await complete_login(
            cfg, code, state, request, db_session
        )
    except OIDCError as exc:
        raise _oidc_http_error(exc)

    payload = {
        "user": user.model_dump() if hasattr(user, "model_dump") else user,
        "tokens": tokens,
        "redirect_url": redirect_url,
    }
    response = JSONResponse(content=jsonable_encoder(payload))
    # Also set the httpOnly cookies directly, so a same-domain callback lands
    # authenticated even before the frontend re-mints them from the JSON body.
    set_auth_cookies(response, tokens["access_token"], tokens["refresh_token"], request)
    return response
