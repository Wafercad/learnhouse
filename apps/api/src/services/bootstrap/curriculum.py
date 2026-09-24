"""LearnHouse owns course/chapter rows; stable identities allow cross-service resume."""

from datetime import datetime
from uuid import NAMESPACE_URL, uuid5
from sqlmodel import select

from src.db.courses.courses import Course
from src.db.courses.chapters import Chapter
from src.db.courses.course_chapters import CourseChapter
from src.db.resource_authors import (
    ResourceAuthor,
    ResourceAuthorshipEnum,
    ResourceAuthorshipStatusEnum,
)
from .protocol import Conflict, dependency, digest, result


def stable(kind, *keys):
    return (
        kind
        + "_"
        + str(uuid5(NAMESPACE_URL, "/".join(map(str, ("wafercad-bootstrap", kind, *keys)))))
    )


def execute(session, request):
    foundation = dependency(request, "foundation_step")
    specification = dependency(request, "spec_step")
    courses = specification.get("courses", [])
    if not courses:
        raise Conflict("curriculum_spec_required")
    definition = digest({"adapter": 1, "spec": specification["definition"]})
    previous, receipt, missing = (
        request["receipt"],
        {"org_id": foundation["org_id"], "courses": {}},
        False,
    )
    for spec in courses:
        key = spec["key"]
        uuid = spec.get("existing_uuid") or stable("course", foundation["org_uuid"], key)
        course = session.exec(select(Course).where(Course.course_uuid == uuid)).one_or_none()
        prior = previous.get("courses", {}).get(key, {})
        if not course and (prior or spec.get("existing_uuid")):
            raise Conflict("course_removed")
        if course and (course.org_id != foundation["org_id"] or prior.get("uuid", uuid) != uuid):
            raise Conflict("course_scope_or_identity_changed")
        if not course:
            missing = True
            if request["action"] == "apply":
                stamp = str(datetime.now())
                course = Course(
                    name=spec["name"],
                    description=spec["name"],
                    about=spec["name"],
                    org_id=foundation["org_id"],
                    course_uuid=uuid,
                    public=False,
                    published=False,
                    open_to_contributors=False,
                    creation_date=stamp,
                    update_date=stamp,
                    extra_metadata={"bootstrap_key": key},
                )
                session.add(course)
                session.flush()
                session.add(
                    ResourceAuthor(
                        resource_uuid=uuid,
                        user_id=foundation["admin_id"],
                        authorship=ResourceAuthorshipEnum.CREATOR,
                        authorship_status=ResourceAuthorshipStatusEnum.ACTIVE,
                        creation_date=stamp,
                        update_date=stamp,
                    )
                )
        if not course:
            continue
        entry = {"uuid": uuid, "id": course.id, "chapters": {}}
        for index, name in enumerate(spec["chapters"]):
            # Existing authored courses are matched by chapter name, but never renamed.
            chapters = session.exec(
                select(Chapter).where(Chapter.course_id == course.id, Chapter.name == name)
            ).all()
            if len(chapters) > 1:
                raise Conflict("ambiguous_authored_chapter")
            chapter = chapters[0] if chapters else None
            old = prior.get("chapters", {}).get(name)
            if old and (chapter is None or old != chapter.id):
                raise Conflict("chapter_removed_or_renamed")
            if chapter is None:
                missing = True
                if request["action"] == "apply":
                    stamp = str(datetime.now())
                    chapter = Chapter(
                        name=name,
                        org_id=foundation["org_id"],
                        course_id=course.id,
                        chapter_uuid=stable("chapter", uuid, name),
                        creation_date=stamp,
                        update_date=stamp,
                    )
                    session.add(chapter)
                    session.flush()
                    session.add(
                        CourseChapter(
                            order=index,
                            course_id=course.id,
                            chapter_id=chapter.id,
                            org_id=foundation["org_id"],
                            creation_date=stamp,
                            update_date=stamp,
                        )
                    )
            if chapter:
                link = session.exec(
                    select(CourseChapter).where(
                        CourseChapter.course_id == course.id, CourseChapter.chapter_id == chapter.id
                    )
                ).one_or_none()
                if not link and request["action"] == "verify":
                    raise Conflict("chapter_placement_missing")
                if chapter.org_id != foundation["org_id"]:
                    raise Conflict("chapter_scope_changed")
                entry["chapters"][name] = chapter.id
        receipt["courses"][key] = entry
    if request["action"] == "apply":
        session.flush()
        return execute(session, {**request, "action": "verify", "receipt": receipt})
    return result(
        "missing" if missing else "ready",
        definition,
        receipt,
        "curriculum_missing" if missing else "ok",
    )
