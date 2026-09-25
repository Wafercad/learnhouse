"""Portable authored content, explicit SSO operator roles, and safe replay."""

from copy import deepcopy

import pytest
from sqlmodel import SQLModel, select

from src.db.courses.assignments import Assignment, AssignmentTask
from src.db.courses.blocks import Block
from src.db.user_organizations import UserOrganization
from src.services.bootstrap import course_pack, foundation
from src.services.bootstrap.course_pack_export import export_pack
from src.services.bootstrap.protocol import Conflict
from src.tests.bootstrap.test_lifecycle import session, request, Activity, Course


def pack():
    assignment = dict(
        assignment_uuid="assignment_test",
        title="Check understanding",
        description="Quiz",
        due_date="2035-12-31",
        published=True,
        grading_type="PERCENTAGE",
        auto_grading=True,
        anti_copy_paste=False,
        show_correct_answers=True,
        allow_retries=False,
        max_retries=0,
        pass_threshold_percentage=None,
        tasks=[
            dict(
                assignment_task_uuid="task_test",
                title="Question",
                description="Choose",
                hint="",
                assignment_type="QUIZ",
                contents={"questions": [{"correct": 1}]},
                max_grade_value=100,
            )
        ],
    )
    return {
        "format": 1,
        "course": dict(
            course_uuid="course_test",
            name="Test course",
            description="Description",
            about="About",
            learnings="",
            tags="",
            chapters=[
                dict(
                    chapter_uuid="chapter_test",
                    name="Start",
                    description="Intro",
                    activities=[
                        dict(
                            activity_uuid="activity_test",
                            name="Quiz",
                            activity_type="TYPE_ASSIGNMENT",
                            activity_sub_type="SUBTYPE_ASSIGNMENT_ANY",
                            content={},
                            details={},
                            published=True,
                            assignment=assignment,
                        )
                    ],
                )
            ],
        ),
    }


def operation(session):
    SQLModel.metadata.create_all(
        session.bind, tables=[Assignment.__table__, AssignmentTask.__table__]
    )
    owner = foundation.execute(session, request())["receipt"]
    session.commit()
    return dict(
        action="verify",
        environment="local",
        scope="fixture:demo-course",
        receipt={},
        data={"foundation_step": "owner", "pack": pack()},
        dependencies={"owner": owner},
    )


def test_course_pack_readonly_then_import_and_replay_preserve_authored_work(session):
    req = operation(session)
    assert course_pack.execute(session, req)["status"] == "missing"
    assert not session.exec(select(Course)).all()
    first = course_pack.execute(session, {**req, "action": "apply"})
    session.commit()
    assert first["status"] == "ready"
    assert not session.exec(select(Course)).one().public
    assert session.exec(select(AssignmentTask)).one().contents == {
        "questions": [{"correct": 1}]
    }
    SQLModel.metadata.create_all(session.bind, tables=[Block.__table__])
    assert export_pack(session, "course_test") == pack()
    session.exec(select(Activity)).one().name = "Author changed title"
    req["receipt"] = first["receipt"]
    assert (
        course_pack.execute(session, {**req, "action": "apply"})["receipt"]
        == first["receipt"]
    )
    assert session.exec(select(Activity)).one().name == "Author changed title"


@pytest.mark.parametrize("change", ["removed", "unpublished", "tenant"])
def test_course_pack_conflicts_never_recreate_or_republish(session, change):
    req = operation(session)
    req["receipt"] = course_pack.execute(session, {**req, "action": "apply"})["receipt"]
    activity = session.exec(select(Activity)).one()
    if change == "removed":
        session.delete(activity)
    elif change == "unpublished":
        activity.published = False
    else:
        activity.org_id = 999
    session.commit()
    with pytest.raises(Conflict):
        course_pack.execute(session, {**req, "action": "apply"})


def test_production_rejected_before_any_writes(session):
    req = operation(session)
    with pytest.raises(Conflict, match="forbidden"):
        course_pack.execute(
            session, {**req, "action": "apply", "environment": "production"}
        )
    assert not session.exec(select(Course)).all()


def test_pack_rejects_hidden_parent_ids_missing_assessments_and_duplicate_ids():
    for change in ("parent", "assessment", "duplicate"):
        value = deepcopy(pack())
        activity = value["course"]["chapters"][0]["activities"][0]
        if change == "parent":
            activity["org_id"] = 10
        elif change == "assessment":
            activity["assignment"] = None
        else:
            activity["activity_uuid"] = "course_test"
        with pytest.raises(Conflict):
            course_pack.validate_pack(value)


def test_explicit_course_author_survives_sso_without_promoting_membership(session):
    req = request()
    req["data"]["operator_role"] = "course_author"
    first = foundation.execute(session, req)
    session.commit()
    membership = session.exec(select(UserOrganization)).one()
    assert membership.role_id == 5
    req["receipt"] = first["receipt"]
    assert foundation.execute(session, {**req, "action": "verify"})["status"] == "ready"
    req["data"]["operator_role"] = "admin"
    with pytest.raises(Conflict, match="administrator_requires_review"):
        foundation.execute(session, req)
    assert membership.role_id == 5


def test_arbitrary_operator_role_rejected(session):
    req = request()
    req["data"]["operator_role"] = "maintainer"
    with pytest.raises(Conflict, match="invalid_operator_role"):
        foundation.execute(session, req)
