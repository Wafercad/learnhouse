"""Wafercad Cloud Campus service-integration token — on-behalf-of trail access.

The campus BFF (``eda-services/campus_service``) drives LearnHouse headlessly with
ONE platform credential (an org-scoped ``lh_`` API token flagged
``is_service_integration``) and must act on a SPECIFIC learner's ``trail`` within
its org. This module provides the two dependencies that make that safe, entirely
behind the ``WAFERCAD_SERVICE_INTEGRATION_ENABLED`` config flag (default false →
stock Community-Edition behaviour):

- ``require_trail_principal`` — the trail router's mount gate. Mirrors
  ``require_authenticated_user`` (401 anon), but admits API tokens ONLY when the
  feature is enabled (so ordinary org tokens still cannot reach trails in CE).
- ``resolve_effective_user`` — the per-endpoint principal. With the
  ``X-On-Behalf-Of-User`` header, a service token acts as the named learner
  (org-bounded + audited); without it, session users are unchanged.

Kept in one module and additive, so upstream rebases stay cheap (see the fork spec
``docs/WAFERCAD_SERVICE_INTEGRATION_TOKEN.md``). Imports of ``auth`` are local to
avoid the circular dependency that module has on this package's siblings.
"""

from typing import Optional, Union

from config.config import get_learnhouse_config
from fastapi import Depends, HTTPException, Request, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from src.core.events.database import get_db_session
from src.db.user_audit_events import UserAuditEventType
from src.db.user_organizations import UserOrganization
from src.db.users import AnonymousUser, APITokenUser, PublicUser, User
from src.services.audit.audit import extract_request_context, record_audit_event

#: Value = the target learner's LearnHouse ``user_uuid`` (preferred) or numeric id.
ON_BEHALF_HEADER = "X-On-Behalf-Of-User"


def _feature_enabled() -> bool:
    config = get_learnhouse_config()
    return bool(config.general_config.wafercad_service_integration_enabled)


def _is_service_token(user: object) -> bool:
    return isinstance(user, APITokenUser) and getattr(
        user, "is_service_integration", False
    )


async def require_trail_principal(
    request: Request,
    db_session: AsyncSession = Depends(get_db_session),
) -> Union[PublicUser, APITokenUser]:
    """Router gate for trail endpoints.

    401 for anonymous (both modes). Admits API tokens ONLY when the
    service-integration feature is enabled — otherwise it behaves exactly like
    ``require_authenticated_user`` (403 for any API token), so stock CE is
    unaffected. ``resolve_effective_user`` then enforces service-token + header.
    """
    from src.security.auth import get_authenticated_user

    user = await get_authenticated_user(request, db_session)
    if isinstance(user, APITokenUser) and not _feature_enabled():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API tokens cannot access this resource.",
        )
    return user


async def resolve_effective_user(
    request: Request,
    db_session: AsyncSession = Depends(get_db_session),
) -> Union[PublicUser, APITokenUser, AnonymousUser]:
    """The effective principal for a trail operation.

    Without ``X-On-Behalf-Of-User``: a session user is returned unchanged; a
    service token is rejected (it must name the learner). With the header: only a
    service-integration token (feature on) may act, and only for a user IN its org
    — the call is audited and the learner is returned as a normal ``PublicUser`` so
    all downstream trail logic runs exactly as it would for that learner.
    """
    from src.security.auth import get_authenticated_user

    user = await get_authenticated_user(request, db_session)
    on_behalf = request.headers.get(ON_BEHALF_HEADER)
    if on_behalf is None:
        if isinstance(user, APITokenUser):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{ON_BEHALF_HEADER} is required for a service token.",
            )
        return user
    if not (_feature_enabled() and _is_service_token(user)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="on-behalf-of requires a service-integration token.",
        )
    return await _act_on_behalf(request, db_session, user, on_behalf)


async def _act_on_behalf(
    request: Request,
    db_session: AsyncSession,
    token: APITokenUser,
    on_behalf: str,
) -> PublicUser:
    target = await _load_user(db_session, on_behalf)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="on-behalf-of user not found.",
        )
    if not await _is_org_member(db_session, target.id, token.org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="on-behalf-of user is not in the token's organization.",
        )
    await _audit(request, token, target)
    return PublicUser(**target.model_dump())


async def _load_user(db_session: AsyncSession, ref: str) -> Optional[User]:
    result = await db_session.execute(select(User).where(User.user_uuid == ref))
    user = result.scalars().first()
    if user is None and ref.isdigit():
        by_id = await db_session.execute(select(User).where(User.id == int(ref)))
        user = by_id.scalars().first()
    return user


async def _is_org_member(
    db_session: AsyncSession,
    user_id: int,
    org_id: int,
) -> bool:
    result = await db_session.execute(
        select(UserOrganization).where(
            UserOrganization.user_id == user_id,
            UserOrganization.org_id == org_id,
        )
    )
    return result.scalars().first() is not None


async def _audit(request: Request, token: APITokenUser, target: User) -> None:
    ip, user_agent = extract_request_context(request)
    await record_audit_event(
        event_type=UserAuditEventType.SERVICE_ON_BEHALF,
        user_id=target.id,
        org_id=token.org_id,
        ip=ip,
        user_agent=user_agent,
        target_uuid=getattr(target, "user_uuid", None),
        metadata={
            "actor": "service_token",
            "token_id": token.id,
            "token_name": token.token_name,
            "created_by_user_id": token.created_by_user_id,
            "action": request.method,
            "path": str(request.url.path),
        },
    )
