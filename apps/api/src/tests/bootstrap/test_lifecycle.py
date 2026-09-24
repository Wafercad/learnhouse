"""Owning-service schema tests: draft content, stable IDs and preservation."""

from copy import deepcopy
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlmodel import SQLModel, Session, select

from src.services.bootstrap import foundation, curriculum, content
from src.services.bootstrap.protocol import Conflict
from src.db.organizations import Organization
from src.db.users import User
from src.db.roles import Role
from src.db.api_tokens import APIToken
from src.db.user_organizations import UserOrganization
from src.db.organization_config import OrganizationConfig
from src.db.courses.courses import Course
from src.db.courses.chapters import Chapter
from src.db.courses.course_chapters import CourseChapter
from src.db.courses.activities import Activity
from src.db.courses.chapter_activities import ChapterActivity
from src.db.resource_authors import ResourceAuthor


@compiles(JSONB, "sqlite")
def jsonb_sqlite(*args, **kwargs):
    return "JSON"


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    models = (
        Organization,
        User,
        Role,
        APIToken,
        UserOrganization,
        OrganizationConfig,
        Course,
        Chapter,
        CourseChapter,
        Activity,
        ChapterActivity,
        ResourceAuthor,
    )
    SQLModel.metadata.create_all(engine, tables=[m.__table__ for m in models])
    with Session(engine) as session:
        yield session
    engine.dispose()


def request():
    return dict(
        action="apply",
        scope="academy:test",
        receipt={},
        data=dict(
            slug="test-academy",
            name="Test Academy",
            admin_email="admin@example.org",
            admin_username="test-operator",
            password_env="ADMIN_PASSWORD",
            service_key_env="CAMPUS_KEY",
        ),
        secrets={"ADMIN_PASSWORD": "Disposable-Password-456", "CAMPUS_KEY": "lh_" + "a" * 43},
    )


def build_structure(session):
    initialized = foundation.execute(session, request())
    assert initialized["status"] == "ready"
    spec = {
        "definition": "test-spec-v1",
        "courses": [
            {
                "key": "path/course",
                "name": "Original course",
                "chapters": ["Introduction"],
                "existing_uuid": None,
            }
        ],
    }
    operation = dict(
        action="apply",
        scope="academy:test:curriculum",
        receipt={},
        data={"foundation_step": "foundation", "spec_step": "spec"},
        dependencies={"foundation": initialized["receipt"], "spec": spec},
    )
    output = curriculum.execute(session, operation)
    assert output["status"] == "ready"
    session.commit()
    return operation, output["receipt"]


def test_foundation_plan_has_no_writes_and_retry_keeps_password(session):
    initial = request()
    initial["action"] = "verify"
    assert foundation.execute(session, initial)["status"] == "missing"
    assert not session.exec(select(Role)).all() and not session.exec(select(Organization)).all()
    output = foundation.execute(session, request())
    session.commit()
    user = session.exec(select(User)).one()
    before = user.password
    user.first_name = "Author edit"
    again = request()
    again["receipt"] = output["receipt"]
    del again["secrets"]["ADMIN_PASSWORD"]
    assert foundation.execute(session, again)["status"] == "ready"
    assert user.password == before and user.first_name == "Author edit"
    assert not user.is_superadmin


@pytest.mark.parametrize(
    "mutation", ["revoke_key", "change_role", "remove_membership", "wrong_key"]
)
def test_access_changes_are_conflicts(session, mutation):
    output = foundation.execute(session, request())
    session.commit()
    again = request()
    again["receipt"] = output["receipt"]
    if mutation == "revoke_key":
        session.exec(select(APIToken)).one().is_active = False
    elif mutation == "change_role":
        role = session.get(Role, 1)
        rights = deepcopy(role.rights)
        rights["users"]["action_delete"] = False
        role.rights = rights
    elif mutation == "wrong_key":
        again["secrets"]["CAMPUS_KEY"] = "lh_" + "b" * 43
    else:
        session.delete(session.exec(select(UserOrganization)).one())
    session.commit()
    with pytest.raises(Conflict):
        foundation.execute(session, again)


def test_structure_can_resume_after_receipt_loss_without_duplicate_courses(session):
    operation, receipt = build_structure(session)
    assert curriculum.execute(session, operation)["receipt"] == receipt
    assert len(session.exec(select(Course)).all()) == 1
    assert len(session.exec(select(Chapter)).all()) == 1
    course = session.exec(select(Course)).one()
    assert not course.published and not course.public
    course.name = "Authored course title"
    session.commit()
    operation["receipt"] = receipt
    assert curriculum.execute(session, operation)["status"] == "ready"
    assert course.name == "Authored course title"
    assert not session.exec(select(Activity)).all()  # Structure never implies content.


def test_nonempty_content_pack_is_separate_and_never_overwrites_authored_body(session):
    _, structure = build_structure(session)
    operation = dict(
        action="apply",
        scope="pack:introduction",
        receipt={},
        data={
            "curriculum_step": "structure",
            "lessons": [
                {
                    "key": "welcome",
                    "course": "path/course",
                    "chapter": "Introduction",
                    "name": "Welcome",
                    "body": "First paragraph.\n\nSecond paragraph.",
                }
            ],
        },
        dependencies={"structure": structure},
    )
    output = content.execute(session, operation)
    assert output["status"] == "ready"
    session.commit()
    activity = session.exec(select(Activity)).one()
    assert activity.content["type"] == "doc" and not activity.published
    activity.content = content.page("Edited by the instructor.")
    session.commit()
    operation["receipt"] = output["receipt"]
    assert content.execute(session, operation)["status"] == "ready"
    assert activity.content == content.page("Edited by the instructor.")
    operation["data"]["lessons"] = []
    with pytest.raises(Conflict, match="nonempty"):
        content.execute(session, operation)


def test_removed_lesson_is_not_recreated(session):
    _, structure = build_structure(session)
    operation = dict(
        action="apply",
        scope="pack:introduction",
        receipt={},
        data={
            "curriculum_step": "structure",
            "lessons": [
                {
                    "key": "welcome",
                    "course": "path/course",
                    "chapter": "Introduction",
                    "name": "Welcome",
                    "body": "Lesson body.",
                }
            ],
        },
        dependencies={"structure": structure},
    )
    output = content.execute(session, operation)
    session.delete(session.exec(select(ChapterActivity)).one())
    session.delete(session.exec(select(Activity)).one())
    session.commit()
    operation["receipt"] = output["receipt"]
    with pytest.raises(Conflict, match="removed"):
        content.execute(session, operation)


@pytest.mark.asyncio
async def test_managed_startup_never_runs_legacy_install_or_role_refresh(monkeypatch):
    from src.core.events import autoinstall

    monkeypatch.setenv("WC_DEPLOYMENT_ENVIRONMENT", "local")
    install, refresh = AsyncMock(), AsyncMock()
    monkeypatch.setattr(autoinstall, "_install_async", install)
    monkeypatch.setattr(autoinstall, "install_default_elements", refresh)
    await autoinstall.auto_install()
    install.assert_not_called()
    refresh.assert_not_called()
