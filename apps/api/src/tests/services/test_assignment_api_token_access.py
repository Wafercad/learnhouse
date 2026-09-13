"""Tests for headless assignment access via org-scoped API tokens.

The assignment authoring + grading service functions used to hard-block every
API token (``_block_api_tokens``). They now route instructor-style access
through ``authorize_assignment_access``, which checks the single ``assignments``
rights bucket and enforces the org boundary via the parent course UUID. The
learner ``/me`` / self-submission / retry endpoints stay session-only.

These tests pin that contract end-to-end against the real test DB:
  - a token with the right ``assignments`` action can author / read / grade;
  - a token missing the action gets 403;
  - a token from another org gets 403 (org boundary);
  - session-only endpoints still 403 for any token, even a fully-privileged one.
"""

from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException

from src.db.courses.assignments import (
    Assignment,
    AssignmentCreate,
    AssignmentRead,
    AssignmentTask,
    AssignmentTaskSubmission,
    AssignmentTaskTypeEnum,
    AssignmentUserSubmission,
    AssignmentUserSubmissionStatus,
    GradingTypeEnum,
)
from src.db.courses.assignments import AssignmentTaskSubmissionUpdate
from src.db.users import APITokenUser, User
from src.db.trails import Trail
from src.services.courses.activities.assignments import (
    create_assignment,
    create_assignment_submission,
    grade_assignment_submission,
    handle_assignment_task_submission,
    put_assignment_task_submission_file,
    read_assignment,
    read_assignment_submissions,
    retry_assignment_submission,
)
from sqlmodel import select

_PATCH_TRAIL_PRESENCE = "src.services.courses.activities.assignments.check_trail_presence"
_PATCH_CERT_CHECK = (
    "src.services.courses.activities.assignments."
    "check_course_completion_and_create_certificate"
)
_PATCH_TRACK = "src.services.courses.activities.assignments.track"
_PATCH_DISPATCH = "src.services.courses.activities.assignments.dispatch_webhooks"

_PATCH_LIMITS = "src.services.courses.activities.assignments.check_limits_with_usage"
_PATCH_INCREASE = "src.services.courses.activities.assignments.increase_feature_usage"
_PATCH_DISPATCH = "src.services.courses.activities.assignments.dispatch_webhooks"
_PATCH_UPLOAD = "src.services.courses.activities.assignments.upload_submission_file"
_PATCH_RBAC = "src.services.courses.activities.assignments.check_resource_access"
_PATCH_ROLES = (
    "src.services.courses.activities.assignments."
    "authorization_verify_based_on_roles"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assignments_rights(create=False, read=False, update=False, delete=False):
    return {
        "action_create": create,
        "action_read": read,
        "action_update": update,
        "action_delete": delete,
    }


def _token(org_id=1, **buckets):
    """Build an APITokenUser whose ``rights`` dict carries the given buckets."""
    return APITokenUser(
        id=1,
        user_uuid="apitoken_test",
        username="api_token",
        org_id=org_id,
        rights=dict(buckets),
        token_name="Test Token",
        created_by_user_id=1,
    )


def _roles(*, read: bool, update: bool):
    """Patch ``authorization_verify_based_on_roles`` per ACTION.

    The submission-file path asks twice with different actions — "read" for
    enrolment and "update" for instructor exemption — so a single return value
    cannot express "enrolled student".
    """
    async def _verify(request, user_id, action, course_uuid, db_session):
        return read if action == "read" else update

    return _verify


class _FakeUpload:
    """The two attributes the submission-file path reads off an UploadFile."""

    def __init__(self, filename: str) -> None:
        self.filename = filename


async def _make_assignment(db, org, course, chapter, activity, *, auto_grading=False):
    a = Assignment(
        title="Headless",
        description="x",
        due_date="2030-01-01",
        published=True,
        grading_type=GradingTypeEnum.NUMERIC,
        auto_grading=auto_grading,
        org_id=org.id,
        course_id=course.id,
        chapter_id=chapter.id,
        activity_id=activity.id,
        assignment_uuid="assignment_token_test",
        creation_date=str(datetime.now()),
        update_date=str(datetime.now()),
    )
    db.add(a)
    await db.commit()
    await db.refresh(a)
    return a


def _assignment_create_obj(org, course, chapter, activity, title="New Assignment"):
    return AssignmentCreate(
        title=title,
        description="Desc",
        due_date="2030-01-01",
        grading_type=GradingTypeEnum.NUMERIC,
        org_id=org.id,
        course_id=course.id,
        chapter_id=chapter.id,
        activity_id=activity.id,
    )


# ---------------------------------------------------------------------------
# Authoring (assignments bucket)
# ---------------------------------------------------------------------------


class TestTokenAuthoring:
    async def test_token_with_create_can_create_assignment(
        self, mock_request, db, org, course, chapter, activity
    ):
        token = _token(assignments=_assignments_rights(create=True))
        obj = _assignment_create_obj(org, course, chapter, activity)
        with patch(_PATCH_LIMITS, new_callable=AsyncMock), \
             patch(_PATCH_INCREASE, new_callable=AsyncMock):
            result = await create_assignment(mock_request, obj, token, db)
        assert isinstance(result, AssignmentRead)
        assert result.title == "New Assignment"

    async def test_token_without_create_is_forbidden(
        self, mock_request, db, org, course, chapter, activity
    ):
        token = _token(assignments=_assignments_rights(read=True))  # no create
        obj = _assignment_create_obj(org, course, chapter, activity)
        with patch(_PATCH_LIMITS, new_callable=AsyncMock), \
             patch(_PATCH_INCREASE, new_callable=AsyncMock):
            with pytest.raises(HTTPException) as exc:
                await create_assignment(mock_request, obj, token, db)
        assert exc.value.status_code == 403

    async def test_token_with_no_assignments_bucket_is_forbidden(
        self, mock_request, db, org, course, chapter, activity
    ):
        # Token has other buckets but not `assignments` at all.
        token = _token(courses={"action_create": True})
        obj = _assignment_create_obj(org, course, chapter, activity)
        with patch(_PATCH_LIMITS, new_callable=AsyncMock), \
             patch(_PATCH_INCREASE, new_callable=AsyncMock):
            with pytest.raises(HTTPException) as exc:
                await create_assignment(mock_request, obj, token, db)
        assert exc.value.status_code == 403

    async def test_cross_org_token_is_forbidden(
        self, mock_request, db, org, other_org, course, chapter, activity
    ):
        # Token belongs to org 2; the course lives in org 1 -> org boundary 403.
        token = _token(org_id=other_org.id, assignments=_assignments_rights(create=True))
        obj = _assignment_create_obj(org, course, chapter, activity)
        with patch(_PATCH_LIMITS, new_callable=AsyncMock), \
             patch(_PATCH_INCREASE, new_callable=AsyncMock):
            with pytest.raises(HTTPException) as exc:
                await create_assignment(mock_request, obj, token, db)
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# Reading (assignments bucket, read action)
# ---------------------------------------------------------------------------


class TestTokenReading:
    async def test_token_with_read_can_read_assignment(
        self, mock_request, db, org, course, chapter, activity
    ):
        await _make_assignment(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(read=True))
        result = await read_assignment(mock_request, "assignment_token_test", token, db)
        assert isinstance(result, AssignmentRead)

    async def test_token_without_read_is_forbidden(
        self, mock_request, db, org, course, chapter, activity
    ):
        await _make_assignment(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(create=True))  # no read
        with pytest.raises(HTTPException) as exc:
            await read_assignment(mock_request, "assignment_token_test", token, db)
        assert exc.value.status_code == 403

    async def test_token_with_read_can_list_submissions(
        self, mock_request, db, org, course, chapter, activity
    ):
        await _make_assignment(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(read=True))
        result = await read_assignment_submissions(
            mock_request, "assignment_token_test", token, db
        )
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Grading (assignments bucket, update action)
# ---------------------------------------------------------------------------


class TestTokenGrading:
    async def _seed_submission(self, db, org, course, chapter, activity, regular_user):
        assignment = await _make_assignment(db, org, course, chapter, activity)
        task = AssignmentTask(
            title="Q1",
            description="What is 2+2?",
            hint="",
            reference_file=None,
            assignment_type=AssignmentTaskTypeEnum.SHORT_ANSWER,
            contents={"correct_answers": ["4"], "match_mode": "exact"},
            max_grade_value=100,
            assignment_id=assignment.id,
            org_id=org.id,
            course_id=course.id,
            chapter_id=chapter.id,
            activity_id=activity.id,
            assignment_task_uuid="assignmenttask_token_test",
            creation_date=str(datetime.now()),
            update_date=str(datetime.now()),
        )
        db.add(task)
        await db.commit()
        await db.refresh(task)

        user_submission = AssignmentUserSubmission(
            user_id=regular_user.id,
            assignment_id=assignment.id,
            grade=0,
            submission_status=AssignmentUserSubmissionStatus.SUBMITTED,
            attempt_number=1,
            assignmentusersubmission_uuid="aus_token_test",
            creation_date=str(datetime.now()),
            update_date=str(datetime.now()),
        )
        db.add(user_submission)
        task_submission = AssignmentTaskSubmission(
            assignment_task_submission_uuid="ats_token_test",
            task_submission={"answer": "4"},  # correct
            grade=0,
            manually_graded=False,
            task_submission_grade_feedback="",
            assignment_type=AssignmentTaskTypeEnum.SHORT_ANSWER,
            user_id=regular_user.id,
            activity_id=task.activity_id,
            course_id=task.course_id,
            chapter_id=task.chapter_id,
            assignment_task_id=task.id,
            creation_date=str(datetime.now()),
            update_date=str(datetime.now()),
        )
        db.add(task_submission)
        await db.commit()
        return assignment

    async def test_token_with_update_can_finalize_grade(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        await self._seed_submission(db, org, course, chapter, activity, regular_user)
        token = _token(assignments=_assignments_rights(update=True))
        with patch(_PATCH_DISPATCH, new_callable=AsyncMock):
            result = await grade_assignment_submission(
                mock_request, regular_user.id, "assignment_token_test", token, db,
                overall_feedback="Nice work",
            )
        # Correct short answer -> full marks, submission marked GRADED.
        assert result["grade"] == 100

    async def test_token_without_update_cannot_grade(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        await self._seed_submission(db, org, course, chapter, activity, regular_user)
        token = _token(assignments=_assignments_rights(read=True))  # no update
        with pytest.raises(HTTPException) as exc:
            await grade_assignment_submission(
                mock_request, regular_user.id, "assignment_token_test", token, db,
            )
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# Session-only endpoints stay blocked for tokens
# ---------------------------------------------------------------------------


class TestTokenSubmitOnBehalf:
    """A token with assignments.create may write a learner's answer by user_id."""

    async def _seed_task(self, db, org, course, chapter, activity):
        assignment = await _make_assignment(db, org, course, chapter, activity)
        task = AssignmentTask(
            title="Q1", description="d", hint="", reference_file=None,
            assignment_type=AssignmentTaskTypeEnum.CUSTOM, contents={"widget": "x"},
            max_grade_value=100, assignment_id=assignment.id, org_id=org.id,
            course_id=course.id, chapter_id=chapter.id, activity_id=activity.id,
            assignment_task_uuid="assignmenttask_obo_test",
            creation_date=str(datetime.now()), update_date=str(datetime.now()),
        )
        db.add(task)
        await db.commit()
        return assignment, task

    async def test_token_submits_task_answer_for_learner(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        await self._seed_task(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(create=True))
        body = AssignmentTaskSubmissionUpdate(task_submission={"answer": "my custom answer"})
        result = await handle_assignment_task_submission(
            mock_request, "assignmenttask_obo_test", body, token, db,
            on_behalf_of_user_id=regular_user.id,
        )
        # Persisted against the LEARNER, not the token.
        assert result.user_id == regular_user.id
        row = (await db.execute(
            select(AssignmentTaskSubmission).where(
                AssignmentTaskSubmission.user_id == regular_user.id
            )
        )).scalars().first()
        assert row is not None
        assert row.task_submission == {"answer": "my custom answer"}

    async def test_token_submit_requires_on_behalf_id(
        self, mock_request, db, org, course, chapter, activity
    ):
        await self._seed_task(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(create=True))
        body = AssignmentTaskSubmissionUpdate(task_submission={"answer": "x"})
        with pytest.raises(HTTPException) as exc:
            await handle_assignment_task_submission(
                mock_request, "assignmenttask_obo_test", body, token, db,
            )
        assert exc.value.status_code == 400

    async def test_token_submit_without_create_right_forbidden(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        await self._seed_task(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(read=True))  # no create
        body = AssignmentTaskSubmissionUpdate(task_submission={"answer": "x"})
        with pytest.raises(HTTPException) as exc:
            await handle_assignment_task_submission(
                mock_request, "assignmenttask_obo_test", body, token, db,
                on_behalf_of_user_id=regular_user.id,
            )
        assert exc.value.status_code == 403

    async def test_token_submit_for_non_member_forbidden(
        self, mock_request, db, org, course, chapter, activity
    ):
        await self._seed_task(db, org, course, chapter, activity)
        # A user with no membership in the token's org.
        outsider = User(
            id=999, username="outsider", first_name="O", last_name="O",
            email="outsider@x.com", password="x", user_uuid="user_outsider",
            creation_date=str(datetime.now()), update_date=str(datetime.now()),
        )
        db.add(outsider)
        await db.commit()
        token = _token(assignments=_assignments_rights(create=True))
        body = AssignmentTaskSubmissionUpdate(task_submission={"answer": "x"})
        with pytest.raises(HTTPException) as exc:
            await handle_assignment_task_submission(
                mock_request, "assignmenttask_obo_test", body, token, db,
                on_behalf_of_user_id=outsider.id,
            )
        assert exc.value.status_code == 403

    async def test_token_submit_unknown_learner_404(
        self, mock_request, db, org, course, chapter, activity
    ):
        await self._seed_task(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(create=True))
        body = AssignmentTaskSubmissionUpdate(task_submission={"answer": "x"})
        with pytest.raises(HTTPException) as exc:
            await handle_assignment_task_submission(
                mock_request, "assignmenttask_obo_test", body, token, db,
                on_behalf_of_user_id=999999,
            )
        assert exc.value.status_code == 404

    async def test_token_creates_assignment_submission_for_learner(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        await _make_assignment(db, org, course, chapter, activity)
        trail = Trail(
            org_id=org.id, user_id=regular_user.id, trail_uuid="trail_obo_test",
            creation_date=str(datetime.now()), update_date=str(datetime.now()),
        )
        db.add(trail)
        await db.commit()
        await db.refresh(trail)
        token = _token(assignments=_assignments_rights(create=True))
        with patch(_PATCH_TRAIL_PRESENCE, new_callable=AsyncMock, return_value=trail), \
             patch(_PATCH_CERT_CHECK, new_callable=AsyncMock), \
             patch(_PATCH_TRACK, new_callable=AsyncMock), \
             patch(_PATCH_DISPATCH, new_callable=AsyncMock):
            result = await create_assignment_submission(
                mock_request, "assignment_token_test", token, db,
                on_behalf_of_user_id=regular_user.id,
            )
        # Aggregate submission created for the LEARNER and marked submitted.
        assert result.submission_status == AssignmentUserSubmissionStatus.SUBMITTED
        assert result.user_id == regular_user.id


class TestSessionOnlyEndpointsStillBlockTokens:
    async def test_retry_blocks_token(
        self, mock_request, db, org, course, chapter, activity
    ):
        # Retry stays session-only — even a full-rights token is rejected.
        await _make_assignment(db, org, course, chapter, activity)
        token = _token(
            assignments=_assignments_rights(create=True, read=True, update=True, delete=True)
        )
        with pytest.raises(HTTPException) as exc:
            await retry_assignment_submission(
                mock_request, "assignment_token_test", token, db
            )
        assert exc.value.status_code == 403


class TestTokenSubmitFileOnBehalf:
    """A token with assignments.create may upload a learner's SUBMISSION FILE.

    The answer write and the file that answer names must be reachable by the same
    callers: a custom frontend that can store ``{"fileUUID": ...}`` but cannot
    upload the file would store an answer pointing at nothing. These mirror
    :class:`TestTokenSubmitOnBehalf` case for case.
    """

    async def _seed_task(self, db, org, course, chapter, activity):
        assignment = await _make_assignment(db, org, course, chapter, activity)
        task = AssignmentTask(
            title="Essay", description="d", hint="", reference_file=None,
            assignment_type=AssignmentTaskTypeEnum.FILE_SUBMISSION, contents={},
            max_grade_value=100, assignment_id=assignment.id, org_id=org.id,
            course_id=course.id, chapter_id=chapter.id, activity_id=activity.id,
            assignment_task_uuid="assignmenttask_file_obo",
            creation_date=str(datetime.now()), update_date=str(datetime.now()),
        )
        db.add(task)
        await db.commit()
        return assignment, task

    async def test_token_uploads_file_for_learner(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        await self._seed_task(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(create=True))
        upload = AsyncMock(return_value="uuid_submission.pdf")
        with patch(_PATCH_UPLOAD, upload):
            result = await put_assignment_task_submission_file(
                mock_request, db, "assignmenttask_file_obo", token,
                _FakeUpload("essay.pdf"),
                on_behalf_of_user_id=regular_user.id,
            )
        assert result == {"file_uuid": "uuid_submission.pdf"}
        assert upload.await_count == 1

    async def test_token_upload_requires_on_behalf_id(
        self, mock_request, db, org, course, chapter, activity
    ):
        await self._seed_task(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(create=True))
        with patch(_PATCH_UPLOAD, AsyncMock()) as upload:
            with pytest.raises(HTTPException) as exc:
                await put_assignment_task_submission_file(
                    mock_request, db, "assignmenttask_file_obo", token,
                    _FakeUpload("essay.pdf"),
                )
        assert exc.value.status_code == 400
        assert upload.await_count == 0

    async def test_token_upload_without_create_right_forbidden(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        await self._seed_task(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(read=True))  # no create
        with patch(_PATCH_UPLOAD, AsyncMock()) as upload:
            with pytest.raises(HTTPException) as exc:
                await put_assignment_task_submission_file(
                    mock_request, db, "assignmenttask_file_obo", token,
                    _FakeUpload("essay.pdf"),
                    on_behalf_of_user_id=regular_user.id,
                )
        assert exc.value.status_code == 403
        assert upload.await_count == 0

    async def test_token_upload_for_non_member_forbidden(
        self, mock_request, db, org, course, chapter, activity
    ):
        await self._seed_task(db, org, course, chapter, activity)
        outsider = User(
            id=998, username="outsider_file", first_name="O", last_name="O",
            email="outsider_file@x.com", password="x", user_uuid="user_outsider_file",
            creation_date=str(datetime.now()), update_date=str(datetime.now()),
        )
        db.add(outsider)
        await db.commit()
        token = _token(assignments=_assignments_rights(create=True))
        with patch(_PATCH_UPLOAD, AsyncMock()):
            with pytest.raises(HTTPException) as exc:
                await put_assignment_task_submission_file(
                    mock_request, db, "assignmenttask_file_obo", token,
                    _FakeUpload("essay.pdf"),
                    on_behalf_of_user_id=outsider.id,
                )
        assert exc.value.status_code == 403

    async def test_token_upload_unknown_learner_404(
        self, mock_request, db, org, course, chapter, activity
    ):
        await self._seed_task(db, org, course, chapter, activity)
        token = _token(assignments=_assignments_rights(create=True))
        with patch(_PATCH_UPLOAD, AsyncMock()):
            with pytest.raises(HTTPException) as exc:
                await put_assignment_task_submission_file(
                    mock_request, db, "assignmenttask_file_obo", token,
                    _FakeUpload("essay.pdf"),
                    on_behalf_of_user_id=999998,
                )
        assert exc.value.status_code == 404

    async def test_token_upload_is_not_blocked_by_a_passed_deadline(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        """The answer path already exempts token writes; the file must match, or a
        learner's answers land and their attachment is refused mid-submission."""
        assignment, _ = await self._seed_task(db, org, course, chapter, activity)
        assignment.due_date = "2000-01-01"
        db.add(assignment)
        await db.commit()
        token = _token(assignments=_assignments_rights(create=True))
        with patch(_PATCH_UPLOAD, AsyncMock(return_value="late.pdf")):
            result = await put_assignment_task_submission_file(
                mock_request, db, "assignmenttask_file_obo", token,
                _FakeUpload("essay.pdf"),
                on_behalf_of_user_id=regular_user.id,
            )
        assert result == {"file_uuid": "late.pdf"}

    async def test_session_student_not_enrolled_is_forbidden(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        """The session gates are untouched by the on-behalf branch."""
        await self._seed_task(db, org, course, chapter, activity)
        with patch(_PATCH_RBAC, new_callable=AsyncMock), \
             patch(_PATCH_ROLES, new_callable=AsyncMock, return_value=False), \
             patch(_PATCH_UPLOAD, AsyncMock()) as upload:
            with pytest.raises(HTTPException) as exc:
                await put_assignment_task_submission_file(
                    mock_request, db, "assignmenttask_file_obo", regular_user,
                    _FakeUpload("essay.pdf"),
                )
        assert exc.value.status_code == 403
        assert "enrolled" in exc.value.detail
        assert upload.await_count == 0

    async def test_session_student_still_blocked_by_a_passed_deadline(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        """Enrolled, not an instructor, past due — the deadline still applies."""
        assignment, _ = await self._seed_task(db, org, course, chapter, activity)
        assignment.due_date = "2000-01-01"
        db.add(assignment)
        await db.commit()
        with patch(_PATCH_RBAC, new_callable=AsyncMock), \
             patch(_PATCH_ROLES, _roles(read=True, update=False)), \
             patch(_PATCH_UPLOAD, AsyncMock()) as upload:
            with pytest.raises(HTTPException) as exc:
                await put_assignment_task_submission_file(
                    mock_request, db, "assignmenttask_file_obo", regular_user,
                    _FakeUpload("essay.pdf"),
                )
        assert exc.value.status_code == 403
        assert exc.value.detail == "Assignment deadline has passed"
        assert upload.await_count == 0

    async def test_404_when_the_assignment_row_is_missing(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        _, task = await self._seed_task(db, org, course, chapter, activity)
        task.assignment_id = 987654
        db.add(task)
        await db.commit()
        with pytest.raises(HTTPException) as exc:
            await put_assignment_task_submission_file(
                mock_request, db, "assignmenttask_file_obo", regular_user,
                _FakeUpload("essay.pdf"),
            )
        assert exc.value.status_code == 404
        assert exc.value.detail == "Assignment not found"

    async def test_404_when_the_course_row_is_missing(
        self, mock_request, db, org, course, chapter, activity, regular_user
    ):
        assignment, _ = await self._seed_task(db, org, course, chapter, activity)
        assignment.course_id = 987654
        db.add(assignment)
        await db.commit()
        with pytest.raises(HTTPException) as exc:
            await put_assignment_task_submission_file(
                mock_request, db, "assignmenttask_file_obo", regular_user,
                _FakeUpload("essay.pdf"),
            )
        assert exc.value.status_code == 404
        assert exc.value.detail == "Course not found"
