"""Create-only text lesson packs; authored activities are never overwritten.

Each pack explicitly lists its lessons. Empty chapter structures cannot satisfy a
content step. Publishing remains an author's separate action.
"""

from datetime import datetime
from sqlmodel import select

from src.db.courses.activities import Activity, ActivityTypeEnum, ActivitySubTypeEnum
from src.db.courses.chapter_activities import ChapterActivity
from src.db.courses.courses import Course
from src.db.courses.chapters import Chapter
from .curriculum import stable
from .protocol import Conflict, dependency, digest, result


def page(body):
    return {
        "type": "doc",
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": block}]}
            for block in body.split("\n\n")
            if block.strip()
        ],
    }


def execute(session, request):
    curriculum = dependency(request, "curriculum_step")
    lessons = request["data"].get("lessons")
    if not isinstance(lessons, list) or not lessons:
        raise Conflict("nonempty_lesson_pack_required")
    if len(lessons) > 500:
        raise Conflict("lesson_pack_too_large")
    keys = set()
    for lesson in lessons:
        if set(lesson) != {"key", "course", "chapter", "name", "body"}:
            raise Conflict("invalid_lesson_spec")
        if (
            not all(isinstance(v, str) and v.strip() for v in lesson.values())
            or lesson["key"] in keys
        ):
            raise Conflict("invalid_or_duplicate_lesson")
        keys.add(lesson["key"])
    definition = digest({"adapter": 1, "lessons": lessons})
    previous, receipt, missing = request["receipt"], {"activities": {}}, False
    for lesson in lessons:
        target = curriculum["courses"].get(lesson["course"], {})
        chapter_id = target.get("chapters", {}).get(lesson["chapter"])
        course = session.get(Course, target.get("id")) if target else None
        chapter = session.get(Chapter, chapter_id) if chapter_id else None
        if (
            course is None
            or chapter is None
            or chapter.course_id != course.id
            or course.org_id != curriculum["org_id"]
            or chapter.org_id != course.org_id
        ):
            raise Conflict("verified_chapter_required")
        uuid = stable("activity", course.course_uuid, request["scope"], lesson["key"])
        activity = session.exec(
            select(Activity).where(Activity.activity_uuid == uuid)
        ).one_or_none()
        prior = previous.get("activities", {}).get(lesson["key"])
        if prior and (not activity or activity.id != prior["id"]):
            raise Conflict("lesson_removed_or_replaced")
        if activity:
            # Keep author edits. The receipt verifies identity and a nonempty body,
            # rather than resetting a changed body to the originally imported text.
            if (
                activity.course_id != course.id
                or activity.org_id != course.org_id
                or activity.activity_sub_type != ActivitySubTypeEnum.SUBTYPE_DYNAMIC_PAGE
                or not (activity.content or {}).get("content")
            ):
                raise Conflict("authored_lesson_requires_review")
            link = session.exec(
                select(ChapterActivity).where(
                    ChapterActivity.chapter_id == chapter.id,
                    ChapterActivity.activity_id == activity.id,
                )
            ).one_or_none()
            if not link:
                raise Conflict("lesson_placement_removed")
        else:
            # A same-name authored lesson is an ambiguity, never a target to replace.
            duplicate = session.exec(
                select(Activity).where(
                    Activity.course_id == course.id, Activity.name == lesson["name"]
                )
            ).first()
            if duplicate:
                raise Conflict("authored_lesson_name_exists")
            missing = True
            if request["action"] == "apply":
                stamp = str(datetime.now())
                activity = Activity(
                    name=lesson["name"],
                    activity_uuid=uuid,
                    org_id=course.org_id,
                    course_id=course.id,
                    activity_type=ActivityTypeEnum.TYPE_DYNAMIC,
                    activity_sub_type=ActivitySubTypeEnum.SUBTYPE_DYNAMIC_PAGE,
                    content=page(lesson["body"]),
                    published=False,
                    creation_date=stamp,
                    update_date=stamp,
                    extra_metadata={
                        "bootstrap_pack": request["scope"],
                        "bootstrap_key": lesson["key"],
                    },
                )
                session.add(activity)
                session.flush()
                links = session.exec(
                    select(ChapterActivity).where(ChapterActivity.chapter_id == chapter.id)
                ).all()
                position = max((row.order for row in links), default=-1) + 1
                session.add(
                    ChapterActivity(
                        activity_id=activity.id,
                        chapter_id=chapter.id,
                        course_id=course.id,
                        org_id=course.org_id,
                        order=position,
                        creation_date=stamp,
                        update_date=stamp,
                    )
                )
        if activity:
            receipt["activities"][lesson["key"]] = {"id": activity.id, "uuid": uuid}
    if request["action"] == "apply":
        session.flush()
        return execute(session, {**request, "action": "verify", "receipt": receipt})
    return result(
        "missing" if missing else "ready",
        definition,
        receipt,
        "lessons_missing" if missing else "ok",
    )
