"""S3 uploads keep processing scratch ephemeral and never fall back to disk."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError
from fastapi import HTTPException
from src.services.utils import upload_content as module


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [False, True])
async def test_s3_scratch_removed_on_success_or_failure(tmp_path, monkeypatch, failure):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module, "get_learnhouse_config", lambda: SimpleNamespace(
        hosting_config=SimpleNamespace(content_delivery=SimpleNamespace(type="s3api"))))
    monkeypatch.setattr(module, "get_s3_bucket_name", lambda: "learning")
    seen = []
    def upload(path, bucket, key, **kwargs):
        seen.append(Path(path))
        assert Path(path).read_bytes() == b"image"
        assert key == "content/orgs/org/avatars/photo.png"
        assert kwargs["ExtraArgs"]["ContentType"] == "image/png"
        if failure:
            raise ClientError({"Error": {"Code": "Unavailable"}}, "PutObject")
    client = Mock(upload_file=Mock(side_effect=upload))
    monkeypatch.setattr(module, "get_storage_client", lambda: client)
    monkeypatch.setattr(module, "ensure_faststart", lambda path: None)
    if failure:
        with pytest.raises(HTTPException) as error:
            await module.upload_content("avatars", "orgs", "org", b"image", "photo.png")
        assert error.value.status_code == 503
    else:
        await module.upload_content("avatars", "orgs", "org", b"image", "photo.png")
    assert seen and all(not path.exists() and not path.parent.exists() for path in seen)
    assert not (tmp_path / "content").exists()
