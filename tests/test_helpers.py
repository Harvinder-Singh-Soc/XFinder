"""Unit tests for utils/helpers.py."""

from __future__ import annotations

import json
import pytest

from utils.helpers import (
    CommandResult,
    chunked,
    dedupe_preserve_order,
    guess_scheme,
    parse_csv_line,
    run_subprocess,
    safe_json_loads,
    safe_jsonl_loads,
    timestamp_str,
    write_json,
)


class TestChunked:
    def test_basic(self) -> None:
        assert list(chunked(range(7), 3)) == [[0, 1, 2], [3, 4, 5], [6]]

    def test_empty(self) -> None:
        assert list(chunked([], 3)) == []

    def test_invalid_size(self) -> None:
        with pytest.raises(ValueError):
            list(chunked([1, 2, 3], 0))


class TestDedupe:
    def test_preserves_order(self) -> None:
        assert dedupe_preserve_order([3, 1, 3, 2, 1]) == [3, 1, 2]

    def test_empty(self) -> None:
        assert dedupe_preserve_order([]) == []


class TestJsonHelpers:
    def test_safe_json_loads_valid(self) -> None:
        assert safe_json_loads('{"a": 1}') == {"a": 1}

    def test_safe_json_loads_invalid(self) -> None:
        assert safe_json_loads("not json") is None
        assert safe_json_loads("") is None

    def test_safe_jsonl_loads_valid(self) -> None:
        text = '{"a": 1}\n{"b": 2}\n\nnot json\n{"c": 3}'
        result = safe_jsonl_loads(text)
        assert len(result) == 3
        assert result[0] == {"a": 1}
        assert result[2] == {"c": 3}

    def test_safe_jsonl_loads_empty(self) -> None:
        assert safe_jsonl_loads("") == []


class TestParseCsvLine:
    def test_basic(self) -> None:
        assert parse_csv_line("a,b ,  c  ") == ["a", "b", "c"]

    def test_empty(self) -> None:
        assert parse_csv_line("") == []


class TestGuessScheme:
    def test_with_scheme(self) -> None:
        assert guess_scheme("https://example.com") == "https://example.com"

    def test_without_scheme(self) -> None:
        assert guess_scheme("example.com") == "https://example.com"
        assert guess_scheme("example.com", prefer_https=False) == "http://example.com"


class TestTimestampStr:
    def test_format(self) -> None:
        from datetime import datetime
        ts = timestamp_str(datetime(2026, 7, 1, 10, 0, 0))
        assert ts == "2026-07-01_10-00-00"


class TestWriteJson:
    def test_writes_valid_json(self, tmp_path) -> None:
        path = tmp_path / "sub" / "test.json"
        data = {"a": 1, "b": [1, 2, 3]}
        result = write_json(path, data)
        assert result.exists()
        with path.open() as f:
            loaded = json.load(f)
        assert loaded == data


class TestRunSubprocess:
    def test_success(self) -> None:
        result = run_subprocess(["echo", "hello"], timeout=5)
        assert result.ok
        assert "hello" in result.stdout

    def test_missing_binary(self) -> None:
        result = run_subprocess(["nonexistent_binary_xyz123"], timeout=5)
        assert not result.ok
        assert result.returncode == 127

    def test_string_command(self) -> None:
        result = run_subprocess("echo hi", timeout=5)
        assert result.ok
        assert "hi" in result.stdout
