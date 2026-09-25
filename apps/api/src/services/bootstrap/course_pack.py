"""Create-only, local fixture course transfer, including assessment definitions.

No users, submissions, progress or uploaded files are accepted. The owner journal
and transaction make replay/resume safe; an edited body is never overwritten.
"""

from datetime import datetime, timezone

from sqlmodel import select

from src.db.courses.activities import Activity
from src.db.courses.assignments import Assignment, AssignmentTask
from src.db.courses.chapter_activities import ChapterActivity
from src.db.courses.chapters import Chapter
from src.db.courses.course_chapters import CourseChapter
from src.db.courses.courses import Course
from src.db.resource_authors import ResourceAuthor
from .protocol import Conflict, dependency, digest, result

FIELDS = {
    "course": "course_uuid name description about learnings tags",
    "chapter": "chapter_uuid name description",
    "activity": "activity_uuid name activity_type activity_sub_type content details published",
    "assignment": (
        "assignment_uuid title description due_date published grading_type auto_grading "
        "anti_copy_paste show_correct_answers allow_retries max_retries pass_threshold_percentage"
    ),
    "task": "assignment_task_uuid title description hint assignment_type contents max_grade_value",
}
MODELS = {
    "course": Course,
    "chapter": Chapter,
    "activity": Activity,
    "assignment": Assignment,
    "task": AssignmentTask,
}
UUIDS = {kind: fields.split()[0] for kind, fields in FIELDS.items()}
CHILDREN = {
    "course": "chapters",
    "chapter": "activities",
    "activity": "assignment",
    "assignment": "tasks",
}
ACTIVITY_TYPES = {
    ("TYPE_DYNAMIC", "SUBTYPE_DYNAMIC_PAGE"),
    ("TYPE_VIDEO", "SUBTYPE_VIDEO_YOUTUBE"),
    ("TYPE_ASSIGNMENT", "SUBTYPE_ASSIGNMENT_ANY"),
}


def validate_pack(pack):
    if (
        not isinstance(pack, dict)
        or set(pack) != {"format", "course"}
        or pack["format"] != 1
    ):
        raise Conflict("invalid_course_pack")
    seen = set()

    def walk(kind, item):
        if not isinstance(item, dict):
            raise Conflict("invalid_course_pack_row")
        if set(item) != set(FIELDS[kind].split()) | (
            {CHILDREN[kind]} if kind in CHILDREN else set()
        ):
            raise Conflict("invalid_course_pack_fields")
        identity = item[UUIDS[kind]]
        if (
            not isinstance(identity, str)
            or not identity
            or len(identity) > 100
            or identity in seen
        ):
            raise Conflict("invalid_course_pack_identity")
        seen.add(identity)
        if len(seen) > 1000:
            raise Conflict("course_pack_too_large")
        if kind == "activity":
            if (item["activity_type"], item["activity_sub_type"]) not in ACTIVITY_TYPES:
                raise Conflict("unsupported_course_pack_activity")
            if item["published"] is not True:
                raise Conflict("course_pack_activity_not_ready")
            assignment = item["assignment"]
            if (assignment is not None) != (item["activity_type"] == "TYPE_ASSIGNMENT"):
                raise Conflict("course_pack_assignment_missing")
            if assignment is not None:
                walk("assignment", assignment)
            elif not item["content"]:
                raise Conflict("course_pack_content_empty")
        elif kind in {"course", "chapter", "assignment"}:
            children = item[CHILDREN[kind]]
            if not isinstance(children, list) or not children:
                raise Conflict("course_pack_empty_structure")
            child_kind = {
                "course": "chapter",
                "chapter": "activity",
                "assignment": "task",
            }[kind]
            for child in children:
                walk(child_kind, child)

    walk("course", pack["course"])


class Importer:
    def __init__(self, session, request, foundation):
        self.session, self.request, self.foundation = session, request, foundation
        self.missing = False
        self.rows = {}
        self.stamp = datetime.now(timezone.utc).isoformat()

    def row(self, kind, item, parents):
        model, uuid_field = MODELS[kind], UUIDS[kind]
        uuid = item[uuid_field]
        row = self.session.exec(
            select(model).where(getattr(model, uuid_field) == uuid)
        ).one_or_none()
        previous = self.request["receipt"].get("rows", {}).get(uuid)
        if previous and (row is None or previous != row.id):
            raise Conflict("course_pack_row_removed_or_replaced")
        if row:
            if any(getattr(row, key) != value for key, value in parents.items()):
                raise Conflict("course_pack_scope_changed")
            if (
                kind == "course"
                and (row.extra_metadata or {}).get("bootstrap_pack")
                != self.request["scope"]
            ):
                raise Conflict("course_pack_authored_course_exists")
            if kind in {"course", "activity", "assignment"} and not row.published:
                raise Conflict("course_pack_content_unpublished")
        else:
            self.missing = True
            if self.request["action"] == "verify":
                return None
            values = {key: item[key] for key in FIELDS[kind].split()}
            values.update(parents, creation_date=self.stamp, update_date=self.stamp)
            if kind == "course":
                values.update(
                    public=False,
                    published=True,
                    open_to_contributors=False,
                    extra_metadata={"bootstrap_pack": self.request["scope"]},
                )
            row = model.model_validate(values)
            self.session.add(row)
            self.session.flush()
            if kind == "course":
                self.session.add(
                    ResourceAuthor(
                        resource_uuid=uuid,
                        user_id=self.foundation["admin_id"],
                        authorship="CREATOR",
                        authorship_status="ACTIVE",
                        creation_date=self.stamp,
                        update_date=self.stamp,
                    )
                )
        self.rows[uuid] = row.id
        return row

    def link(self, model, parents, order):
        link = self.session.exec(select(model).filter_by(**parents)).one_or_none()
        if link is None:
            if self.request["receipt"].get("rows"):
                raise Conflict("course_pack_placement_removed")
            self.missing = True
            if self.request["action"] == "apply":
                self.session.add(
                    model(
                        **parents,
                        order=order,
                        creation_date=self.stamp,
                        update_date=self.stamp
                    )
                )

    def import_course(self, item):
        root = {"org_id": self.foundation["org_id"]}
        course = self.row("course", item, root)
        if course is None:
            return None
        root = {**root, "course_id": course.id}
        for index, spec in enumerate(item["chapters"]):
            chapter = self.row("chapter", spec, root)
            if chapter is None:
                continue
            parents = {**root, "chapter_id": chapter.id}
            self.link(CourseChapter, parents, index)
            for position, entry in enumerate(spec["activities"]):
                activity = self.row("activity", entry, root)
                if activity is None:
                    continue
                attached = {**parents, "activity_id": activity.id}
                self.link(ChapterActivity, attached, position)
                if entry["assignment"] is not None:
                    assignment = self.row("assignment", entry["assignment"], attached)
                    if assignment:
                        for task in entry["assignment"]["tasks"]:
                            self.row(
                                "task",
                                task,
                                {**attached, "assignment_id": assignment.id},
                            )
        return course


def execute(session, request):
    if request.get("environment") not in {"local", "stage"}:
        raise Conflict("test_fixtures_forbidden")
    if set(request["data"]) != {"foundation_step", "pack"}:
        raise Conflict("invalid_course_pack_spec")
    foundation = dependency(request, "foundation_step")
    pack = request["data"]["pack"]
    validate_pack(pack)
    importer = Importer(session, request, foundation)
    course = importer.import_course(pack["course"])
    receipt = {"rows": importer.rows}
    if course:
        receipt.update(
            course_uuid=course.course_uuid,
            title=course.name,
            published=course.published,
            description=course.description,
            chapters=len(pack["course"]["chapters"]),
        )
    if request["action"] == "apply":
        session.flush()
        return execute(session, {**request, "action": "verify", "receipt": receipt})
    return result(
        "missing" if importer.missing else "ready",
        digest({"adapter": 1, "pack": pack}),
        receipt,
        "course_pack_missing" if importer.missing else "ok",
    )
