from fastapi import UploadFile
from src.services.utils.upload_content import delete_content, upload_file


async def upload_thumbnail(thumbnail_file: UploadFile, org_uuid: str, course_id: int) -> str:
    """Upload a course thumbnail image with file validation."""
    return await upload_file(
        file=thumbnail_file,
        directory=f"courses/{course_id}/thumbnails",
        type_of_dir="orgs",
        uuid=org_uuid,
        allowed_types=["image", "video"],
        filename_prefix="thumbnail",
    )


async def delete_thumbnail(name_in_disk: str, org_uuid: str, course_id: str) -> bool:
    """Remove a previously uploaded course thumbnail from storage.

    Paired with `upload_thumbnail` so the two agree on the directory; every
    upload writes a fresh uuid4-prefixed name, so without this a replace left
    the old file behind forever with nothing referencing it.
    """
    if not name_in_disk:
        return False
    return await delete_content(
        directory=f"courses/{course_id}/thumbnails",
        type_of_dir="orgs",
        uuid=org_uuid,
        file_and_format=name_in_disk,
    )
