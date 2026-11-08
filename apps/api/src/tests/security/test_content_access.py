"""Real database checks for media hierarchy, publication and tenant authorization."""
import pytest
from fastapi import HTTPException
from src.db.courses.activities import Activity, ActivityTypeEnum, ActivitySubTypeEnum
from src.db.podcasts.podcasts import Podcast
from src.db.podcasts.episodes import PodcastEpisode
from src.db.users import AnonymousUser, APITokenUser
from src.db.usergroups import UserGroup
from src.db.usergroup_resources import UserGroupResource
from src.security.content_access import check_content_access


@pytest.fixture
async def lesson(db, course, org):
    value = Activity(id=451, name="Lesson", activity_uuid="activity_media",
        course_id=course.id, org_id=org.id, published=True,
        activity_type=ActivityTypeEnum.TYPE_CUSTOM,
        activity_sub_type=ActivitySubTypeEnum.SUBTYPE_CUSTOM)
    db.add(value)
    await db.commit()
    return value


def path(org, course, lesson):
    return f"orgs/{org.org_uuid}/courses/{course.course_uuid}/activities/{lesson.activity_uuid}/video/a.mp4"


async def test_public_published_lesson_and_catalogue(db, org, course, lesson):
    await check_content_access(path(org, course, lesson), AnonymousUser(), db)
    await check_content_access(f"orgs/{org.org_uuid}/courses/{course.course_uuid}/thumbnails/a.png", AnonymousUser(), db)


async def test_wrong_org_missing_and_wrong_parent_child_denied(db, org, other_org, course, lesson, admin_user):
    value = path(org, course, lesson)
    for bad in [value.replace(org.org_uuid, other_org.org_uuid),
                value.replace(lesson.activity_uuid, "activity_missing"),
                value.replace(course.course_uuid, "course_missing"),
                value.replace("/activities/", "/secret/")]:
        with pytest.raises(HTTPException) as error:
            await check_content_access(bad, admin_user, db)
        assert error.value.status_code == 403


async def test_private_lesson_requires_real_course_grant(db, org, course, lesson, regular_user, admin_user):
    course.public = False
    db.add(course)
    db.add(UserGroup(id=77, org_id=org.id, name="Enrolled learners", description="Restricted"))
    db.add(UserGroupResource(usergroup_id=77, org_id=org.id, resource_uuid=course.course_uuid))
    await db.commit()
    for caller in [AnonymousUser(), regular_user, APITokenUser(org_id=999)]:
        try:
            await check_content_access(path(org, course, lesson), caller, db)
        except HTTPException:
            continue
        pytest.fail(f"Unexpected grant for {type(caller).__name__}")
    await check_content_access(path(org, course, lesson), admin_user, db)


async def test_unpublished_lesson_needs_edit_permission(db, org, course, lesson, regular_user, admin_user):
    lesson.published = False
    db.add(lesson)
    await db.commit()
    for caller in [AnonymousUser(), regular_user]:
        with pytest.raises(HTTPException):
            await check_content_access(path(org, course, lesson), caller, db)
    await check_content_access(path(org, course, lesson), admin_user, db)


async def test_public_course_draft_not_anonymous(db, org, course, lesson):
    course.published = False
    db.add(course)
    await db.commit()
    with pytest.raises(HTTPException):
        await check_content_access(path(org, course, lesson), AnonymousUser(), db)


async def test_podcast_hierarchy_and_publication(db, org, other_org):
    podcast = Podcast(id=92, name="Podcast", org_id=org.id, podcast_uuid="podcast_media",
                      public=True, published=True)
    episode = PodcastEpisode(id=93, title="Episode", org_id=org.id, podcast_id=92,
                             episode_uuid="episode_media", published=True)
    db.add(podcast)
    db.add(episode)
    await db.commit()
    value = f"orgs/{org.org_uuid}/podcasts/podcast_media/episodes/episode_media/audio/a.mp3"
    await check_content_access(value, AnonymousUser(), db)
    for bad in [value.replace(org.org_uuid, other_org.org_uuid), value.replace("episode_media", "episode_missing")]:
        with pytest.raises(HTTPException):
            await check_content_access(bad, AnonymousUser(), db)
    episode.published = False
    db.add(episode)
    await db.commit()
    with pytest.raises(HTTPException):
        await check_content_access(value, AnonymousUser(), db)


@pytest.mark.parametrize("value", [
    "orgs/org/logos/logo.png", "orgs/org/landing/intro.mp4",
    "users/user/avatars/avatar.png",
])
async def test_only_designated_public_media_paths(db, value):
    await check_content_access(value, AnonymousUser(), db)


@pytest.mark.parametrize("value", [
    "orgs/org/private/secret.pdf", "orgs/org/media/random/video.mp4",
    "users/user/export.zip", "users/user/avatars/script.html", "misc/file.txt",
])
async def test_unknown_paths_fail_closed(db, value):
    with pytest.raises(HTTPException) as error:
        await check_content_access(value, AnonymousUser(), db)
    assert error.value.status_code == 401

async def test_restricted_course_membership_revocation(db, org, course, lesson, regular_user):
    from src.db.usergroup_user import UserGroupUser
    course.public = False
    group = UserGroup(id=78, org_id=org.id, name="Learners", description="Enrolled")
    db.add(course)
    db.add(group)
    db.add(UserGroupResource(usergroup_id=78, org_id=org.id, resource_uuid=course.course_uuid))
    member = UserGroupUser(usergroup_id=78, user_id=regular_user.id, org_id=org.id)
    db.add(member)
    await db.commit()
    await check_content_access(path(org, course, lesson), regular_user, db)
    await db.delete(member)
    await db.commit()
    with pytest.raises(HTTPException):
        await check_content_access(path(org, course, lesson), regular_user, db)


async def test_library_media_uses_owner_org_and_resource_policy(db, org, other_org):
    from src.db.media.media import Media
    media = Media(id=71, name="Preview", media_uuid="media_preview", org_id=org.id, public=True)
    db.add(media)
    await db.commit()
    value = f"orgs/{org.org_uuid}/media/media_preview/a.png"
    await check_content_access(value, AnonymousUser(), db)
    for bad in [value.replace(org.org_uuid, other_org.org_uuid),
                value.replace("media_preview", "media_missing"),
                value.replace("media_preview", "course_wrong")]:
        with pytest.raises(HTTPException):
            await check_content_access(bad, AnonymousUser(), db)


async def test_incomplete_child_path_and_submission_require_checks(db, org, course, lesson):
    value = path(org, course, lesson)
    with pytest.raises(HTTPException):
        await check_content_access(value.rsplit("/", 2)[0], AnonymousUser(), db)
    submission = value.rsplit("/", 2)[0] + "/assignments/assignment_x/tasks/task_x/subs/file.pdf"
    with pytest.raises(HTTPException):
        await check_content_access(submission, AnonymousUser(), db)


async def test_playground_thumbnail_reuses_publication_and_access(db, org, other_org, regular_user):
    from src.db.playgrounds import Playground, PlaygroundAccessType
    pg = Playground(id=811, name="Media qualification", org_id=org.id,
                    playground_uuid="playground_media", created_by=regular_user.id,
                    access_type=PlaygroundAccessType.PUBLIC, published=True)
    db.add(pg)
    await db.commit()
    value = f"orgs/{org.org_uuid}/playgrounds/playground_media/thumbnails/a.png"
    await check_content_access(value, AnonymousUser(), db)
    for bad in [value.replace(org.org_uuid, other_org.org_uuid),
                value.replace("playground_media", "missing"),
                value.replace("/thumbnails/", "/private/"),
                value.replace("a.png", "script.html")]:
        with pytest.raises(HTTPException):
            await check_content_access(bad, AnonymousUser(), db)
    with pytest.raises(HTTPException):
        await check_content_access(value, APITokenUser(org_id=other_org.id), db)
    pg.published = False
    db.add(pg)
    await db.commit()
    with pytest.raises(HTTPException):
        await check_content_access(value, AnonymousUser(), db)
    await check_content_access(value, regular_user, db)
    pg.published = True
    pg.access_type = PlaygroundAccessType.RESTRICTED
    db.add(pg)
    await db.commit()
    with pytest.raises(HTTPException):
        await check_content_access(value, AnonymousUser(), db)
    await check_content_access(value, regular_user, db)
