"""Atomic Academy organization, default roles, administrator and scoped credential."""

from datetime import datetime
from copy import deepcopy
import json
from uuid import NAMESPACE_URL, uuid5, uuid4

from sqlalchemy import text
from sqlmodel import select
from src.db.organizations import Organization
from src.db.organization_config import OrganizationConfig, OrganizationConfigV2Base
from src.db.roles import Role
from src.db.users import User
from src.db.user_organizations import UserOrganization
from src.db.api_tokens import APIToken
from src.security.security import (
    security_hash_password,
    security_hash_token,
    security_verify_token,
)
from src.services.setup.default_roles import desired_roles
from .protocol import Conflict, digest, result


def service_rights(roles):
    rights = deepcopy(next(r.rights for r in roles if r.id == 4))
    # Current Campus clients provision/detach users, manage cohorts and assignments.
    for resource in ("users", "usergroups", "assignments"):
        rights[resource] = {key: True for key in rights[resource]}
    for resource in ("courses", "coursechapters", "activities"):
        rights[resource]["action_create"] = True
        rights[resource]["action_update"] = True
    rights["dashboard"]["action_access"] = False
    return rights


def execute(session, request):
    data, previous = request["data"], request["receipt"]
    if set(data) - {"operator_role"} != {
        "slug",
        "name",
        "admin_email",
        "admin_username",
        "password_env",
        "service_key_env",
    }:
        raise Conflict("invalid_foundation_spec")
    # The Academy operator can be the platform's federated course author.
    # Match the explicitly selected role; never promote or rewrite a membership.
    role_id = {"admin": 1, "course_author": 5}.get(data.get("operator_role", "admin"))
    if role_id is None:
        raise Conflict("invalid_operator_role")
    roles = desired_roles()
    definition = digest(
        {
            "roles": {r.role_uuid: r.rights for r in roles},
            "service_rights": service_rights(roles),
        }
    )
    receipt, missing = {}, False
    for desired in roles:
        role = session.get(Role, desired.id)
        if role and (
            role.role_uuid != desired.role_uuid or role.rights != desired.rights
        ):
            raise Conflict("existing_role_rights_require_review")
        if not role:
            if previous.get("roles"):
                raise Conflict("role_removed")
            missing = True
    org = session.exec(
        select(Organization).where(Organization.slug == data["slug"])
    ).one_or_none()
    owner_uuid = "org_" + str(
        uuid5(NAMESPACE_URL, "wafercad:" + request["scope"] + ":" + data["slug"])
    )
    if org and previous.get("org_uuid", org.org_uuid) != org.org_uuid:
        raise Conflict("organization_identity_changed")
    if not org and previous.get("org_uuid"):
        raise Conflict("organization_removed")
    user = session.exec(
        select(User).where(User.email == data["admin_email"].lower())
    ).one_or_none()
    membership = None
    config = None
    key = None
    if org:
        config = session.exec(
            select(OrganizationConfig).where(OrganizationConfig.org_id == org.id)
        ).one_or_none()
        key = session.exec(
            select(APIToken).where(
                APIToken.org_id == org.id, APIToken.name == "Wafercad Campus"
            )
        ).one_or_none()
        receipt.update(org_id=org.id, org_uuid=org.org_uuid, slug=org.slug)
        if user:
            membership = session.exec(
                select(UserOrganization).where(
                    UserOrganization.user_id == user.id,
                    UserOrganization.org_id == org.id,
                )
            ).one_or_none()
    if user and (
        not membership
        or membership.role_id != role_id
        or user.username != data["admin_username"]
        or user.locked_until
    ):
        raise Conflict("existing_administrator_requires_review")
    if user:
        if previous.get("admin_id", user.id) != user.id:
            raise Conflict("administrator_identity_changed")
        receipt["admin_id"] = user.id
    elif previous.get("admin_id"):
        raise Conflict("administrator_removed")
    rights = service_rights(roles)
    if key:
        if (
            not key.is_active
            or not key.is_service_integration
            or key.expires_at
            or key.rights != rights
        ):
            raise Conflict("service_access_changed_or_revoked")
        if previous.get("access_id", key.id) != key.id:
            raise Conflict("service_access_identity_changed")
        supplied = request.get("secrets", {}).get(data["service_key_env"])
        if not supplied:
            raise Conflict("configured_service_key_required")
        if not security_verify_token(supplied, key.token_hash):
            raise Conflict("configured_service_key_mismatch")
        receipt["access_id"] = key.id
    elif previous.get("access_id"):
        raise Conflict("service_access_removed")
    missing = missing or not all((org, config, user, membership, key))
    if org and missing and org.org_uuid != owner_uuid:
        raise Conflict("existing_organization_incomplete")
    if not missing:
        receipt["roles"] = [r.id for r in roles]
        return result("ready", definition, receipt)
    if request["action"] == "verify":
        return result("missing", definition, receipt, "foundation_missing")
    supplied = request.get("secrets", {})
    password = supplied.get(data["password_env"], "")
    raw_key = supplied.get(data["service_key_env"], "")
    if not user and len(password) < 12:
        raise Conflict("administrator_password_required")
    if not key and (not raw_key.startswith("lh_") or len(raw_key) < 40):
        raise Conflict("service_key_required")
    if (
        not user
        and session.exec(
            select(User).where(User.username == data["admin_username"])
        ).first()
    ):
        raise Conflict("administrator_username_exists")
    stamp = str(datetime.now())
    for desired in roles:
        if not session.get(Role, desired.id):
            session.add(desired)
    session.flush()
    if session.bind.dialect.name == "postgresql":
        # Legacy global roles use fixed IDs. Preserve the sequence high-water
        # mark so subsequent authored/custom roles cannot collide with them.
        sequence = session.execute(
            text("SELECT pg_get_serial_sequence('role', 'id')")
        ).scalar()
        if sequence:
            session.execute(
                text(
                    "SELECT setval(CAST(:sequence AS regclass), "
                    "GREATEST((SELECT max(id) FROM role), nextval(CAST(:sequence AS regclass))), true)"
                ),
                {"sequence": sequence},
            )
    if not org:
        org = Organization(
            name=data["name"],
            slug=data["slug"],
            email=data["admin_email"],
            org_uuid=owner_uuid,
            creation_date=stamp,
            update_date=stamp,
        )
        session.add(org)
        session.flush()
    if not config:
        session.add(
            OrganizationConfig(
                org_id=org.id,
                config=json.loads(
                    OrganizationConfigV2Base(
                        config_version="2.0", plan="free"
                    ).model_dump_json()
                ),
                creation_date=stamp,
                update_date=stamp,
            )
        )
    if not user:
        user = User(
            username=data["admin_username"],
            email=data["admin_email"].lower(),
            first_name="",
            last_name="",
            password=security_hash_password(password),
            user_uuid="user_" + str(uuid4()),
            email_verified=False,
            is_superadmin=False,
            creation_date=stamp,
            update_date=stamp,
        )
        session.add(user)
        session.flush()
        session.add(
            UserOrganization(
                user_id=user.id,
                org_id=org.id,
                role_id=role_id,
                creation_date=stamp,
                update_date=stamp,
            )
        )
    if not key:
        session.add(
            APIToken(
                name="Wafercad Campus",
                org_id=org.id,
                created_by_user_id=user.id,
                token_uuid="apitoken_" + str(uuid4()),
                token_prefix=raw_key[:12],
                token_hash=security_hash_token(raw_key),
                rights=rights,
                is_service_integration=True,
                is_active=True,
                creation_date=stamp,
                update_date=stamp,
            )
        )
    session.flush()
    return execute(session, {**request, "action": "verify"})
