import logging
from datetime import datetime
import json
from uuid import uuid4
from fastapi import HTTPException
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from src.db.organization_config import (
    OrganizationConfig,
    OrganizationConfigV2Base,
)
from src.db.organizations import Organization, OrganizationCreate
from src.db.roles import DashboardPermission, Permission, PermissionsWithOwn, Rights, Role, RoleTypeEnum
from src.db.user_organizations import UserOrganization
from src.db.users import User, UserCreate, UserRead
from src.security.security import security_hash_password
from src.security.rbac.constants import ADMIN_ROLE_ID


# Install Default roles
async def install_default_elements(db_session: AsyncSession):
    """Explicit legacy role upgrade; normal application startup does not call it."""
    from src.services.setup.default_roles import desired_roles
    for desired in desired_roles():
        existing = await db_session.get(Role, desired.id)
        if existing:
            for field in ("name", "description", "role_type", "role_uuid", "rights", "update_date"):
                setattr(existing, field, getattr(desired, field))
        else:
            db_session.add(desired)
    await db_session.commit()
    return True


# Organization creation
async def install_create_organization(org_object: OrganizationCreate, db_session: AsyncSession):
    org = Organization.model_validate(org_object)

    # Complete the org object
    org.org_uuid = f"org_{uuid4()}"
    org.creation_date = str(datetime.now())
    org.update_date = str(datetime.now())

    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)

    # Org Config (v2 format)
    org_config = OrganizationConfigV2Base(
        config_version="2.0",
        plan="free",
    )

    org_config = json.loads(org_config.model_dump_json())

    # OrgSettings
    org_settings = OrganizationConfig(
        org_id=int(org.id if org.id else 0),
        config=org_config,
        creation_date=str(datetime.now()),
        update_date=str(datetime.now()),
    )

    db_session.add(org_settings)
    await db_session.commit()
    await db_session.refresh(org_settings)

    return org


async def install_create_organization_user(
    user_object: UserCreate,
    org_slug: str,
    db_session: AsyncSession,
    is_superadmin: bool = False,
):
    user = User.model_validate(user_object)

    # Complete the user object
    user.user_uuid = f"user_{uuid4()}"
    user.password = security_hash_password(user_object.password)
    user.email_verified = False
    user.is_superadmin = is_superadmin
    user.creation_date = str(datetime.now())
    user.update_date = str(datetime.now())

    # Verifications

    # Check if Organization exists
    statement = select(Organization).where(Organization.slug == org_slug)
    org = (await db_session.execute(statement)).scalars().first()

    if not org:
        raise HTTPException(
            status_code=409,
            detail="Organization does not exist",
        )

    # Username
    statement = select(User).where(User.username == user.username)
    existing_user = (await db_session.execute(statement)).scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username already exists",
        )

    # Email
    statement = select(User).where(User.email == user.email)
    existing_email = (await db_session.execute(statement)).scalars().first()

    if existing_email:
        raise HTTPException(
            status_code=409,
            detail="Email already exists",
        )

    # Exclude unset values
    user_data = user.model_dump(exclude_unset=True)
    for key, value in user_data.items():
        setattr(user, key, value)

    # Add user to database
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # get org id
    statement = select(Organization).where(Organization.slug == org_slug)
    org = (await db_session.execute(statement)).scalars().first()
    org_id = org.id if org else 0

    # Link user and organization
    user_organization = UserOrganization(
        user_id=user.id if user.id else 0,
        org_id=org_id or 0,
        role_id=ADMIN_ROLE_ID,
        creation_date=str(datetime.now()),
        update_date=str(datetime.now()),
    )

    db_session.add(user_organization)
    await db_session.commit()
    await db_session.refresh(user_organization)

    # This install/seed user is an org ADMIN — add them to the Loops marketing
    # audience. Best-effort, SaaS-gated (no-op on OSS/self-hosted), never fails
    # the install.
    try:
        from src.services.marketing.loops import record_org_admin_in_loops
        record_org_admin_in_loops(
            email=getattr(user, "email", None),
            org_slug=org_slug,
            first_name=getattr(user, "first_name", None),
            last_name=getattr(user, "last_name", None),
        )
    except Exception:
        pass

    user = UserRead.model_validate(user)

    return user

