"""Router tests for src/routers/content_files.py."""

from types import SimpleNamespace
from io import BytesIO
import urllib.parse

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from src.core.events.database import get_db_session
from src.db.courses.courses import Course
from src.db.podcasts.podcasts import Podcast
from src.db.users import APITokenUser, AnonymousUser, PublicUser
from src.routers import content_files
from src.routers.content_files import router as content_files_router
from src.security.auth import get_current_user


@pytest.fixture
def app(db, admin_user):
    app = FastAPI()
    app.include_router(content_files_router)
    app.dependency_overrides[get_db_session] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: admin_user
    yield app
    app.dependency_overrides.clear()


@pytest.fixture
async def client(app):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


class _Body:
    def __init__(self, data: bytes):
        self._data = BytesIO(data)

    def read(self, size=-1):
        return self._data.read(size)

    def close(self):
        pass


class _S3Client:
    def __init__(self, payload: bytes = b"abcdef"):
        self.payload = payload

    def head_object(self, Bucket, Key):
        return {"ContentLength": len(self.payload)}

    def get_object(self, Bucket, Key, Range):
        start_end = Range.replace("bytes=", "").split("-")
        start = int(start_end[0])
        end = int(start_end[1])
        return {"Body": _Body(self.payload[start : end + 1])}


class _EmptyBody:
    def read(self, size=-1):
        return b""

    def close(self):
        pass


class _EmptyS3Client:
    def head_object(self, Bucket, Key):
        return {"ContentLength": 4}

    def get_object(self, Bucket, Key, Range):
        return {"Body": _EmptyBody()}


class _PathTrigger(str):
    def __new__(cls):
        return str.__new__(cls, "safe\\path")

    def __contains__(self, item):
        if item == "..":
            return False
        return super().__contains__(item)

    def replace(self, old, new, count=-1):
        if old == "\\" and new == "/":
            return "safe../path"
        return super().replace(old, new, count)


class TestContentFilesRouter:
    def test_validate_content_path_branches(self):
        assert content_files._validate_content_path("orgs/abc/file.txt") == "orgs/abc/file.txt"
        assert content_files._validate_content_path("../secret.txt") is None
        assert content_files._validate_content_path("foo%2f..%2fbar.txt") is None

        with pytest.MonkeyPatch.context() as mp:
            def fake_realpath(path):
                if path == "content":
                    return "/tmp/content"
                if path == "/tmp/content/safe.txt":
                    return "/tmp/other/safe.txt"
                return path

            mp.setattr(content_files.os.path, "realpath", fake_realpath)
            assert content_files._validate_content_path("safe.txt") is None

        with pytest.MonkeyPatch.context() as mp:
            def fake_unquote(value):
                return value if isinstance(value, _PathTrigger) else _PathTrigger()

            mp.setattr(urllib.parse, "unquote", fake_unquote)
            assert content_files._validate_content_path("safe.txt") is None

    async def test_stream_full_and_range_content(
        self, client, db, org, course
    ):
        s3_client = _S3Client(b"abcdef")
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(content_files, "get_storage_client", lambda: s3_client)
            mp.setattr(content_files, "get_s3_bucket_name", lambda: "bucket")
            full_response = await client.get(
                f"/content/orgs/{org.org_uuid}/courses/{course.course_uuid}/thumbnails/thumb.png"
            )
            range_response = await client.get(
                f"/content/orgs/{org.org_uuid}/courses/{course.course_uuid}/thumbnails/thumb.png",
                headers={"range": "bytes=1-3"},
            )
            suffix_range_response = await client.get(
                f"/content/orgs/{org.org_uuid}/courses/{course.course_uuid}/thumbnails/thumb.png",
                headers={"range": "bytes=-2"},
            )

        assert full_response.status_code == 200
        assert full_response.content == b"abcdef"
        assert range_response.status_code == 206
        assert range_response.content == b"bcd"
        assert range_response.headers["content-range"] == "bytes 1-3/6"
        assert suffix_range_response.status_code == 206
        assert suffix_range_response.content == b"ef"

    async def test_open_ended_range_invalid_range_and_empty_streams(
        self, client, app
    ):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(content_files, "get_storage_client", lambda: _S3Client())
            mp.setattr(content_files, "get_s3_bucket_name", lambda: "bucket")
            open_ended_response = await client.get(
                "/content/users/u/avatars/avatar.png",
                headers={"range": "bytes=2-"},
            )
            invalid_range_response = await client.get(
                "/content/users/u/avatars/avatar.png",
                headers={"range": "bytes=bad"},
            )

        assert open_ended_response.status_code == 206
        assert open_ended_response.content == b"cdef"
        assert open_ended_response.headers["content-range"] == "bytes 2-5/6"
        assert invalid_range_response.status_code == 200
        assert invalid_range_response.content == b"abcdef"
        assert "content-range" not in invalid_range_response.headers

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(content_files, "get_storage_client", lambda: _EmptyS3Client())
            mp.setattr(content_files, "get_s3_bucket_name", lambda: "bucket")
            with pytest.raises(OSError, match="Incomplete object-storage response"):
                await client.get("/content/users/u/avatars/avatar.png")
            with pytest.raises(OSError, match="Incomplete object-storage response"):
                await client.get("/content/users/u/avatars/avatar.png", headers={"range": "bytes=0-2"})

    async def test_head_and_invalid_path_handling(self, client):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(content_files, "get_storage_client", lambda: _S3Client())
            mp.setattr(content_files, "get_s3_bucket_name", lambda: "bucket")
            head_response = await client.head("/content/users/u/avatars/avatar.png")
            bad_path_response = await client.get("/content/%2E%2E/secrets.txt")
            bad_head_response = await client.head("/content/%2E%2E/secrets.txt")
            mp.setattr(content_files, "get_storage_client", lambda: None)
            no_storage_head_response = await client.head("/content/users/u/avatars/avatar.png")

        assert head_response.status_code == 200
        assert head_response.headers["content-length"] == "6"
        assert bad_path_response.status_code == 400
        assert bad_head_response.status_code == 400
        assert no_storage_head_response.status_code == 500

    async def test_storage_no_such_key_returns_404(self, client):
        from botocore.exceptions import ClientError

        class _NotFoundS3Client:
            def head_object(self, Bucket, Key):
                raise ClientError(
                    {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}},
                    "HeadObject",
                )

            def get_object(self, Bucket, Key, Range):
                raise ClientError(
                    {"Error": {"Code": "NoSuchKey", "Message": "Not Found"}},
                    "GetObject",
                )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(content_files, "get_storage_client", lambda: _NotFoundS3Client())
            mp.setattr(content_files, "get_s3_bucket_name", lambda: "bucket")
            get_404 = await client.get("/content/users/u/avatars/avatar.png")
            head_404 = await client.head("/content/users/u/avatars/avatar.png")

        assert get_404.status_code == 404
        assert head_404.status_code == 404

    async def test_storage_client_errors_return_correct_status(self, client):
        from botocore.exceptions import ClientError

        class _AccessDeniedS3Client:
            def head_object(self, Bucket, Key):
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Forbidden"}},
                    "HeadObject",
                )

            def get_object(self, Bucket, Key, Range):
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Forbidden"}},
                    "GetObject",
                )

        class _OtherClientErrorS3Client:
            def head_object(self, Bucket, Key):
                raise ClientError(
                    {"Error": {"Code": "InternalError", "Message": "Oops"}},
                    "HeadObject",
                )

            def get_object(self, Bucket, Key, Range):
                raise ClientError(
                    {"Error": {"Code": "InternalError", "Message": "Oops"}},
                    "GetObject",
                )

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(content_files, "get_storage_client", lambda: _AccessDeniedS3Client())
            mp.setattr(content_files, "get_s3_bucket_name", lambda: "bucket")
            get_403 = await client.get("/content/users/u/avatars/avatar.png")
            head_403 = await client.head("/content/users/u/avatars/avatar.png")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(content_files, "get_storage_client", lambda: _OtherClientErrorS3Client())
            mp.setattr(content_files, "get_s3_bucket_name", lambda: "bucket")
            get_502 = await client.get("/content/users/u/avatars/avatar.png")
            head_502 = await client.head("/content/users/u/avatars/avatar.png")

        assert get_403.status_code == 403
        assert head_403.status_code == 403
        assert get_502.status_code == 502
        assert head_502.status_code == 502

    async def test_storage_head_errors_return_502(self, client):
        class _BrokenS3Client:
            def head_object(self, Bucket, Key):
                raise Exception("boom")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(content_files, "get_storage_client", lambda: _BrokenS3Client())
            mp.setattr(content_files, "get_s3_bucket_name", lambda: "bucket")
            get_response = await client.get("/content/users/u/avatars/avatar.png")
            head_response = await client.head("/content/users/u/avatars/avatar.png")

        # Generic storage failures are surfaced as 502 (Bad Gateway). 404 is
        # reserved for cases where the storage layer reported NoSuchKey.
        assert get_response.status_code == 502
        assert head_response.status_code == 502

    async def test_private_course_requires_auth_and_storage_configuration(
        self, client, db, org, app
    ):
        course = Course(
            id=30,
            name="Private S3 Course",
            description="Desc",
            public=False,
            published=True,
            open_to_contributors=False,
            org_id=org.id,
            course_uuid="course_private_s3",
            creation_date="2024-01-01",
            update_date="2024-01-01",
        )
        db.add(course)
        await db.commit()

        from src.routers import content_files

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(content_files, "get_s3_bucket_name", lambda: "bucket")
            app.dependency_overrides[get_current_user] = lambda: AnonymousUser()
            anon_response = await client.get(
                f"/content/orgs/{org.org_uuid}/courses/{course.course_uuid}/activities/activity_x/video.mp4"
            )

            app.dependency_overrides[get_current_user] = lambda: AnonymousUser()
            mp.setattr(content_files, "get_storage_client", lambda: None)
            no_storage_response = await client.get(
                f"/content/orgs/{org.org_uuid}/courses/{course.course_uuid}/thumbnails/thumb.png"
            )

        assert anon_response.status_code == 401
        assert no_storage_response.status_code == 500
