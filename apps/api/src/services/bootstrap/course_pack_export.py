"""Read-only portable course data for the explicit local fixture importer.

This deliberately rejects uploads/blocks rather than producing a partial copy.
Only authored content is exported; identity, access and learner records stay put.
"""

from sqlmodel import select

from src.db.courses.activities import Activity
from src.db.courses.assignments import Assignment, AssignmentTask
from src.db.courses.blocks import Block
from src.db.courses.chapter_activities import ChapterActivity
from src.db.courses.chapters import Chapter
from src.db.courses.course_chapters import CourseChapter
from src.db.courses.courses import Course
from .course_pack import FIELDS, validate_pack
from .protocol import Conflict


def fields(kind, row):
    serialized = row.model_dump(mode="json")
    return {name: serialized[name] for name in FIELDS[kind].split()}


def export_pack(session, course_uuid):
    course = session.exec(select(Course).where(Course.course_uuid == course_uuid)).one()
    if course.thumbnail_image or course.thumbnail_video:
        raise Conflict("course_pack_uploaded_media_requires_transfer")
    output = fields("course", course)
    chapters = session.exec(
        select(Chapter, CourseChapter)
        .join(CourseChapter, CourseChapter.chapter_id == Chapter.id)
        .where(CourseChapter.course_id == course.id)
        .order_by(CourseChapter.order)
    ).all()
    output["chapters"] = []
    for chapter, _ in chapters:
        if chapter.org_id != course.org_id or chapter.thumbnail_image:
            raise Conflict("course_pack_chapter_requires_review")
        item = fields("chapter", chapter)
        item["activities"] = []
        activities = session.exec(
            select(Activity, ChapterActivity)
            .join(ChapterActivity, ChapterActivity.activity_id == Activity.id)
            .where(ChapterActivity.chapter_id == chapter.id)
            .order_by(ChapterActivity.order)
        ).all()
        for activity, _ in activities:
            if activity.course_id != course.id or activity.org_id != course.org_id:
                raise Conflict("course_pack_activity_scope_mismatch")
            if session.exec(
                select(Block).where(Block.activity_id == activity.id)
            ).first():
                raise Conflict("course_pack_blocks_require_transfer")
            entry = fields("activity", activity)
            assignment = session.exec(
                select(Assignment).where(Assignment.activity_id == activity.id)
            ).one_or_none()
            entry["assignment"] = None
            if assignment:
                if (
                    assignment.course_id != course.id
                    or assignment.org_id != course.org_id
                ):
                    raise Conflict("course_pack_assignment_scope_mismatch")
                assessment = fields("assignment", assignment)
                tasks = session.exec(
                    select(AssignmentTask)
                    .where(AssignmentTask.assignment_id == assignment.id)
                    .order_by(AssignmentTask.id)
                ).all()
                if any(task.reference_file for task in tasks):
                    raise Conflict("course_pack_uploaded_media_requires_transfer")
                assessment["tasks"] = [fields("task", task) for task in tasks]
                entry["assignment"] = assessment
            item["activities"].append(entry)
        output["chapters"].append(item)
    pack = {"format": 1, "course": output}
    validate_pack(pack)
    return pack
