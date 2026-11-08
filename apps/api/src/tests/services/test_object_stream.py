from io import BytesIO
from unittest.mock import Mock
import pytest
from src.services.utils.object_stream import byte_range, normalize_range_header, stream_object

@pytest.mark.parametrize("value,size,expected", [
    (None, 10, (0,9)), ("bytes=0-2", 10, (0,2)), ("bytes=4-", 10, (4,9)),
    ("bytes=-3", 10, (7,9)), ("bytes=-100", 10, (0,9)), ("bytes=2-100", 10, (2,9)),
    ("bytes=bad", 10, (0,9)), ("bytes=0-1,4-5", 10, (0,9)),
    ("bytes="+("9"*100)+"-", 10, None),
    ("bytes=0-"+("9"*100), 10, (0,9)),
    ("bytes=-"+("9"*100), 10, (0,9)),
    ("bytes=10-", 10, None), ("bytes=5-3", 10, None), ("bytes=-0", 10, None),
    ("bytes=0-0", 0, None), (None, 0, (0,-1)), ("bytes=-", 10, (0,9)),
])
def test_range_contract(value, size, expected):
    if expected is None:
        with pytest.raises(ValueError):
            byte_range(value, size)
    else:
        assert byte_range(value, size) == expected


def test_stream_uses_one_get_and_bounded_reads():
    body = Mock(wraps=BytesIO(b"0123456789"))
    client = Mock()
    client.get_object.return_value = {"Body": body}
    assert b"".join(stream_object(client, "bucket", "key", 0, 9, 3)) == b"0123456789"
    client.get_object.assert_called_once_with(Bucket="bucket", Key="key", Range="bytes=0-9")
    assert [call.args[0] for call in body.read.call_args_list] == [3,3,3,1]
    body.close.assert_called_once()


def test_cancelled_stream_closes_connection():
    body = Mock(wraps=BytesIO(b"abcdef"))
    client = Mock()
    client.get_object.return_value = {"Body": body}
    stream = stream_object(client, "bucket", "key", 0, 5, 2)
    assert next(stream) == b"ab"
    stream.close()
    body.close.assert_called_once()


@pytest.mark.parametrize("failure", [None, OSError("connection lost")])
def test_truncated_or_failed_read_closes_connection(failure):
    body = Mock(wraps=BytesIO(b"x"))
    if failure:
        body.read.side_effect = failure
    client = Mock()
    client.get_object.return_value = {"Body": body}
    with pytest.raises(OSError):
        list(stream_object(client, "bucket", "key", 0, 9, 3))
    body.close.assert_called_once()


def test_empty_object_needs_no_get():
    client = Mock()
    assert list(stream_object(client, "bucket", "key", 0, -1, 3)) == []
    client.get_object.assert_not_called()
    with pytest.raises(ValueError):
        list(stream_object(client, "bucket", "key", 0, 1, 0))
