"""Bounded-memory media reads and one-range HTTP parsing."""
import re

_RANGE = re.compile(r"bytes=(\d*)-(\d*)")


def normalize_range_header(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    match = _RANGE.fullmatch(value)
    if not match or not any(match.groups()):
        return None  # Ignore malformed or unsupported multipart Range.
    return value


def byte_range(value: str | None, size: int) -> tuple[int, int]:
    """Return an inclusive range; raise ValueError for unsatisfiable requests."""
    normalized = normalize_range_header(value)
    if normalized is None:
        return 0, size - 1
    if size <= 0:
        raise ValueError("Unsatisfiable range")
    start_text, end_text = normalized[6:].split("-")
    # Headers are bounded by the edge, but do not construct unbounded integers.
    def bounded(text):
        return int(text) if len(text) <= 20 else size + 1
    if not start_text:
        suffix = bounded(end_text)
        if suffix == 0:
            raise ValueError("Unsatisfiable suffix")
        return max(0, size - suffix), size - 1
    start = bounded(start_text)
    end = min(bounded(end_text), size - 1) if end_text else size - 1
    if start >= size or start > end:
        raise ValueError("Unsatisfiable range")
    return start, end


def stream_object(client, bucket: str, key: str, start: int, end: int, chunk_size: int):
    """One S3 GET, bounded reads, and release on completion, failure or cancel."""
    if chunk_size < 1:
        raise ValueError("Chunk size must be positive")
    if end < start:
        return
    response = client.get_object(Bucket=bucket, Key=key, Range=f"bytes={start}-{end}")
    body = response["Body"]
    try:
        remaining = end - start + 1
        while remaining:
            data = body.read(min(chunk_size, remaining))
            if not data or len(data) > remaining:
                raise OSError("Incomplete object-storage response")
            remaining -= len(data)
            yield data
    finally:
        body.close()
