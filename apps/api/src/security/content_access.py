"""Authorize media against its organization and owning learning resource."""
from pathlib import PurePosixPath

from fastapi import HTTPException, Request
from sqlmodel import select

from src.db.courses.activities import Activity
from src.db.courses.courses import Course
from src.db.organizations import Organization
from src.db.podcasts.episodes import PodcastEpisode
from src.db.podcasts.podcasts import Podcast
from src.db.users import AnonymousUser, APITokenUser
from src.security.rbac import AccessAction, check_resource_access
from src.security.submission_file_access import is_submission_file, enforce_submission_file_access

_PUBLIC_BRANDING = {"logos", "thumbnails", "previews", "landing",
                    "auth_backgrounds", "og_images", "favicons"}
_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".ico"}


def _deny(user):
    raise HTTPException(status_code=401 if isinstance(user, AnonymousUser) else 403,
                        detail="Media access denied")


async def authorize_learning_media(parts, user, db, request):
    """Resolve every supplied hierarchy component before checking resource RBAC."""
    is_course = parts[2] == "courses"
    parent_model, uuid_field = (Course, Course.course_uuid) if is_course else (Podcast, Podcast.podcast_uuid)
    parent = (await db.execute(select(parent_model).join(
        Organization, parent_model.org_id == Organization.id
    ).where(uuid_field == parts[3], Organization.org_uuid == parts[1]))).scalars().first()
    if parent is None:
        _deny(user)
    parent_uuid = parts[3]
    child_kind = "activities" if is_course else "episodes"
    if len(parts) > 4 and parts[4] == child_kind:
        if len(parts) < 7:
            _deny(user)
        model, uuid_col, parent_col = (
            (Activity, Activity.activity_uuid, Activity.course_id) if is_course else
            (PodcastEpisode, PodcastEpisode.episode_uuid, PodcastEpisode.podcast_id)
        )
        child = (await db.execute(select(model).where(
            uuid_col == parts[5], parent_col == parent.id, model.org_id == parent.org_id
        ))).scalars().first()
        if child is None:
            _deny(user)
        if not child.published:
            # A course enrolment does not publish an unfinished lesson.
            await check_resource_access(request, db, user, parent_uuid, AccessAction.UPDATE)
    elif (len(parts) == 6 and parts[4] == "thumbnails" and parent.published
          and PurePosixPath(parts[-1]).suffix.lower() in _IMAGE_EXTENSIONS | {".mp4", ".webm"}):
        return  # Published catalogue artwork, not lesson material.
    else:
        _deny(user)
    if isinstance(user, AnonymousUser) and not (parent.public and parent.published):
        _deny(user)
    await check_resource_access(request, db, user, parent_uuid, AccessAction.READ)


async def check_content_access(file_path, current_user, db_session, request=None):
    """Public branding is explicit; private content never falls through to public."""
    parts = file_path.split("/")
    request = request or Request({"type": "http", "headers": []})
    if is_submission_file(parts):
        await authorize_learning_media(parts, current_user, db_session, request)
        await enforce_submission_file_access(parts, current_user, db_session, request)
        return
    if len(parts) >= 4 and parts[0] == "orgs":
        if parts[2] in {"courses", "podcasts"}:
            await authorize_learning_media(parts, current_user, db_session, request)
            return
        if (len(parts) == 6 and parts[2] == "playgrounds"
                and parts[4] == "thumbnails"
                and PurePosixPath(parts[-1]).suffix.lower() in _IMAGE_EXTENSIONS):
            from src.db.playgrounds import Playground
            from src.services.playgrounds.playgrounds import get_playground
            owner_org = (await db_session.execute(select(Organization.id).join(
                Playground, Playground.org_id == Organization.id
            ).where(Organization.org_uuid == parts[1],
                    Playground.playground_uuid == parts[3]))).scalars().first()
            if owner_org is None or (
                isinstance(current_user, APITokenUser) and current_user.org_id != owner_org
            ):
                _deny(current_user)
            # Reuse publication, group membership, ownership and MFA rules.
            await get_playground(request, parts[3], current_user, db_session)
            return
        if parts[2] in {"media", "folders", "boards", "communities"}:
            from src.security.rbac.config import get_resource_type
            from src.security.rbac.utils import get_element_organization_id
            if get_resource_type(parts[3]) != parts[2]:
                _deny(current_user)
            org_id = await get_element_organization_id(parts[3], db_session)
            org = (await db_session.execute(select(Organization.id).where(
                Organization.id == org_id, Organization.org_uuid == parts[1]
            ))).scalars().first()
            if org is None:
                _deny(current_user)
            await check_resource_access(request, db_session, current_user, parts[3], AccessAction.READ)
            return
        if len(parts) == 4 and parts[2] in _PUBLIC_BRANDING:
            return
    if (len(parts) == 4 and parts[0] == "users" and parts[2] == "avatars"
            and PurePosixPath(parts[-1]).suffix.lower() in _IMAGE_EXTENSIONS):
        return
    _deny(current_user)
