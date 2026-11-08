"""
Content Files Router

Serves static content files from S3 storage when S3 is enabled.
Replaces the StaticFiles mount for S3 deployments.

SECURITY:
- Activity content uses the same publication, enrolment and RBAC checks as lessons
- Published catalogue thumbnails are public; drafts require author access
- Only explicit org branding paths are public
- Podcast episode content for non-public podcasts requires auth
"""

import os
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse, Response
from pathlib import Path
from sqlmodel import select
from botocore.exceptions import ClientError

from sqlmodel.ext.asyncio.session import AsyncSession
from src.core.events.database import get_db_session
from src.db.courses.courses import Course
from src.db.podcasts.podcasts import Podcast
from src.db.users import AnonymousUser, PublicUser, APITokenUser
from src.security.content_access import check_content_access as _check_content_access
from src.security.auth import get_current_user
from src.security.submission_file_access import (
    is_submission_file,
    enforce_submission_file_access,
)
from src.services.courses.transfer.storage_utils import (
    get_storage_client,
    get_s3_bucket_name,
)

from src.services.utils.media_delivery import PRIVATE_MEDIA_HEADERS, content_headers
from src.services.utils.object_stream import normalize_range_header, byte_range, stream_object

router = APIRouter()

# MIME type mapping
MIME_TYPES = {
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.mov': 'video/quicktime',
    '.avi': 'video/x-msvideo',
    '.mkv': 'video/x-matroska',
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.aac': 'audio/aac',
    '.flac': 'audio/flac',
    '.m4a': 'audio/mp4',
    '.ogg': 'audio/ogg',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.pdf': 'application/pdf',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.zip': 'application/zip',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.txt': 'text/plain',
}

CHUNK_SIZE = 1024 * 1024  # 1MB


def _get_mime_type(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return MIME_TYPES.get(ext, 'application/octet-stream')


def _validate_content_path(file_path: str) -> str | None:
    """Validate and sanitize path, preventing directory traversal.

    Returns the sanitized relative path string, or None if the path is unsafe.
    """
    from urllib.parse import unquote
    # Decode any URL-encoded characters to catch %2e%2e etc.
    decoded = unquote(unquote(file_path))  # Double-decode to catch double-encoding
    if '..' in decoded or decoded.startswith('/') or '\x00' in decoded:
        return None
    # Normalize path separators
    normalized = decoded.replace('\\', '/')
    if '..' in normalized:
        return None
    # Canonicalize via os.path.realpath (resolves symlinks, normalizes) and verify containment.
    # realpath is used deliberately: it is a recognized path-injection sanitizer.
    base_real = os.path.realpath(str(Path("content")))
    full_real = os.path.realpath(os.path.join(base_real, normalized))
    if not full_real.startswith(base_real + os.sep):
        return None
    # Return the validated relative path
    return os.path.relpath(full_real, base_real)


@router.get(
    "/content/{file_path:path}",
    summary="Serve a content file",
    description="Streams a content file (videos, PDFs, images, etc.) from S3 storage. Supports HTTP Range requests for video/audio seeking. Access is enforced based on the path prefix: activity and podcast episode content require authentication and org membership for non-public resources, while course metadata and org branding are public.",
    responses={
        200: {"description": "File streamed successfully"},
        206: {"description": "Partial content returned for a Range request"},
        400: {"description": "Invalid or unsafe file path"},
        401: {"description": "Authentication required to access this file"},
        403: {"description": "User is not permitted to access this file"},
        404: {"description": "File not found in storage"},
        500: {"description": "Storage backend is not configured"},
    },
)
async def serve_content_file(
    request: Request,
    file_path: str,
    current_user: PublicUser | AnonymousUser | APITokenUser = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db_session),
):
    """
    Serve content files from S3 storage.

    Supports HTTP Range requests for video/audio seeking.
    """
    safe_path = _validate_content_path(file_path)
    if safe_path is None:
        raise HTTPException(status_code=400, detail="Invalid path")

    await _check_content_access(safe_path, current_user, db_session, request=request)

    s3_key = f"content/{safe_path}"
    s3_client = get_storage_client()
    bucket = get_s3_bucket_name()

    if not s3_client:
        raise HTTPException(status_code=500, detail="Storage not configured")

    # Get file metadata
    try:
        head = await asyncio.to_thread(s3_client.head_object, Bucket=bucket, Key=s3_key)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchKey", "404"):
            raise HTTPException(status_code=404, detail="File not found")
        elif code in ("AccessDenied", "403"):
            raise HTTPException(status_code=403, detail="Access denied")
        else:
            raise HTTPException(status_code=502, detail="Storage service error")
    except Exception:
        raise HTTPException(status_code=502, detail="Storage service error")

    file_size = head['ContentLength']
    mime_type = _get_mime_type(safe_path)

    headers = {
        "Accept-Ranges": "bytes",
        "Content-Type": mime_type,
        **content_headers(mime_type),
    }

    range_header = normalize_range_header(request.headers.get("range"))
    try:
        start, end = byte_range(range_header, file_size)
    except ValueError:
        return Response(status_code=416, headers={
            **PRIVATE_MEDIA_HEADERS, "Content-Range": f"bytes */{file_size}",
        })
    headers["Content-Length"] = str(max(0, end - start + 1))
    if range_header:
        headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"
    return StreamingResponse(
        stream_object(s3_client, bucket, s3_key, start, end, CHUNK_SIZE),
        status_code=206 if range_header else 200,
        headers=headers, media_type=mime_type,
    )


@router.head(
    "/content/{file_path:path}",
    summary="Get content file metadata",
    description="Returns metadata for a content file without the body. Used by clients to probe file size, MIME type, and Range support before issuing a GET.",
    responses={
        200: {"description": "File metadata returned via response headers"},
        400: {"description": "Invalid or unsafe file path"},
        401: {"description": "Authentication required to access this file"},
        403: {"description": "User is not permitted to access this file"},
        404: {"description": "File not found in storage"},
        500: {"description": "Storage backend is not configured"},
    },
)
async def head_content_file(
    request: Request,
    file_path: str,
    current_user: PublicUser | AnonymousUser | APITokenUser = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db_session),
):
    """HEAD request for content files - returns metadata without body."""
    safe_path = _validate_content_path(file_path)
    if safe_path is None:
        raise HTTPException(status_code=400, detail="Invalid path")

    await _check_content_access(safe_path, current_user, db_session, request=request)

    s3_key = f"content/{safe_path}"
    s3_client = get_storage_client()
    bucket = get_s3_bucket_name()

    if not s3_client:
        raise HTTPException(status_code=500, detail="Storage not configured")

    try:
        head = await asyncio.to_thread(s3_client.head_object, Bucket=bucket, Key=s3_key)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchKey", "404"):
            raise HTTPException(status_code=404, detail="File not found")
        elif code in ("AccessDenied", "403"):
            raise HTTPException(status_code=403, detail="Access denied")
        else:
            raise HTTPException(status_code=502, detail="Storage service error")
    except Exception:
        raise HTTPException(status_code=502, detail="Storage service error")

    file_size = head['ContentLength']
    mime_type = _get_mime_type(safe_path)

    return Response(
        status_code=200,
        headers={
            "Accept-Ranges": "bytes",
            "Content-Length": str(file_size),
            "Content-Type": mime_type,
            **content_headers(mime_type),
        },
    )
