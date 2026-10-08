"""Tests for src/common/file_utils.py — read/write helpers."""

import csv
import os

import pytest

from src.common.exceptions import FileProcessingError
from src.common.file_utils import latest_files, read_csv, read_json, write_csv, write_csv_stream, write_json, write_markdown


class TestWriteMarkdown:
    """write_markdown must share the error contract of its write_json sibling."""

    def test_writes_content_verbatim(self, tmp_path):
        target = tmp_path / "report.md"
        content = "# Title\n\n| A | B |\n| --- | --- |\n"

        write_markdown(str(target), content)

        assert target.read_text(encoding="utf-8") == content

    def test_creates_missing_parent_directories(self, tmp_path):
        target = tmp_path / "nested" / "deeper" / "report.md"

        write_markdown(str(target), "# Title")

        assert target.read_text(encoding="utf-8") == "# Title"

    def test_unwritable_path_raises_file_processing_error(self, tmp_path):
        # A directory where the file should be makes open() fail with OSError.
        target = tmp_path / "report.md"
        target.mkdir()

        with pytest.raises(FileProcessingError, match="report.md"):
            write_markdown(str(target), "# Title")

    def test_non_ascii_content_round_trips(self, tmp_path):
        target = tmp_path / "report.md"

        write_markdown(str(target), "— ✓ namespace")

        assert target.read_text(encoding="utf-8") == "— ✓ namespace"


class TestWriteJsonSerialisationErrors:
    """F2: a non-serialisable value must not escape as a bare TypeError.

    write_json wraps OSError in FileProcessingError, but a TypeError from
    json.dump bypassed that contract entirely, so callers catching
    FileProcessingError saw an unhandled crash instead.
    """

    def test_unserialisable_value_raises_file_processing_error(self, tmp_path):
        target = tmp_path / "out.json"
        with pytest.raises(FileProcessingError, match="cannot be serialised"):
            write_json(str(target), {"bad": object()})

    def test_error_names_the_target_file(self, tmp_path):
        target = tmp_path / "out.json"
        with pytest.raises(FileProcessingError, match="out.json"):
            write_json(str(target), {"bad": {1, 2, 3}})  # sets are not JSON

    def test_valid_data_still_writes(self, tmp_path):
        target = tmp_path / "out.json"
        write_json(str(target), {"ok": [1, 2, 3]})
        assert read_json(str(target)) == {"ok": [1, 2, 3]}


class TestReadCsv:
    """F3: read_csv is the counterpart to read_json."""

    def test_round_trips_with_write_csv(self, tmp_path):
        target = tmp_path / "out.csv"
        rows = [{"name": "alpha", "count": "1"}, {"name": "beta", "count": "2"}]
        write_csv(str(target), rows)
        assert read_csv(str(target)) == rows

    def test_missing_file_raises_file_processing_error(self, tmp_path):
        with pytest.raises(FileProcessingError, match="Failed to read or parse"):
            read_csv(str(tmp_path / "nope.csv"))

    def test_empty_file_returns_empty_list(self, tmp_path):
        target = tmp_path / "empty.csv"
        target.write_text("")
        assert read_csv(str(target)) == []

    def test_header_only_returns_empty_list(self, tmp_path):
        target = tmp_path / "header.csv"
        target.write_text("name,count\n")
        assert read_csv(str(target)) == []


class TestWriteCsvStream:
    """F4: rows can be streamed rather than materialised."""

    def test_accepts_a_generator(self, tmp_path):
        target = tmp_path / "stream.csv"

        def rows():
            for i in range(3):
                yield {"idx": i, "name": f"row-{i}"}

        write_csv_stream(str(target), rows(), ["idx", "name"])
        assert read_csv(str(target)) == [
            {"idx": "0", "name": "row-0"},
            {"idx": "1", "name": "row-1"},
            {"idx": "2", "name": "row-2"},
        ]

    def test_does_not_consume_input_twice(self, tmp_path):
        """A generator can only be walked once — proves no len()/indexing."""
        target = tmp_path / "stream.csv"
        consumed = []

        def rows():
            for i in range(2):
                consumed.append(i)
                yield {"idx": i}

        write_csv_stream(str(target), rows(), ["idx"])
        assert consumed == [0, 1]

    def test_missing_keys_become_empty_cells(self, tmp_path):
        """F1: restval keeps a short row from raising mid-write."""
        target = tmp_path / "sparse.csv"
        write_csv_stream(str(target), [{"a": "1"}, {"a": "2", "b": "3"}], ["a", "b"])
        assert read_csv(str(target)) == [{"a": "1", "b": ""}, {"a": "2", "b": "3"}]

    def test_writes_header_even_with_no_rows(self, tmp_path):
        target = tmp_path / "headeronly.csv"
        write_csv_stream(str(target), iter([]), ["a", "b"])
        assert target.read_text().strip() == "a,b"


class TestWriteCsvWrapper:
    """write_csv is now a thin wrapper; its behaviour must not have shifted."""

    def test_derives_headers_from_first_row(self, tmp_path):
        target = tmp_path / "out.csv"
        write_csv(str(target), [{"x": "1", "y": "2"}])
        with open(target, newline="") as f:
            assert next(csv.reader(f)) == ["x", "y"]

    def test_explicit_headers_win(self, tmp_path):
        target = tmp_path / "out.csv"
        write_csv(str(target), [{"x": "1", "y": "2"}], headers=["y", "x"])
        with open(target, newline="") as f:
            assert next(csv.reader(f)) == ["y", "x"]

    def test_no_data_and_no_headers_writes_nothing(self, tmp_path):
        target = tmp_path / "out.csv"
        write_csv(str(target), [])
        assert not target.exists()


class TestLatestFiles:
    """latest_files: newest first, fnmatch on the basename, optional mtime ceiling, never raises."""

    NOW = 1_800_000_000.0

    def _touch(self, directory, name, age):
        path = directory / name
        path.write_text("{}")
        os.utime(path, (self.NOW - age, self.NOW - age))
        return str(path)

    def test_newest_first_and_limited_to_n(self, tmp_path):
        a = self._touch(tmp_path, "c-full-findings-1.json", 300)
        b = self._touch(tmp_path, "c-full-findings-2.json", 200)
        c = self._touch(tmp_path, "c-full-findings-3.json", 100)
        pattern = "*-full-findings-*.json"
        assert latest_files(str(tmp_path), pattern) == [c]
        assert latest_files(str(tmp_path), pattern, n=2) == [c, b]
        assert latest_files(str(tmp_path), pattern, n=10) == [c, b, a]
        assert latest_files(str(tmp_path), pattern, n=0) == []

    def test_pattern_matches_the_basename_only_and_skips_directories(self, tmp_path):
        keep = self._touch(tmp_path, "c-full-findings-1.json", 100)
        self._touch(tmp_path, "c-namespace-findings-1.json", 50)
        self._touch(tmp_path, "c-full-findings-1.md", 50)
        self._touch(tmp_path, "C-FULL-FINDINGS-2.JSON", 10)  # case-sensitive on every OS
        (tmp_path / "x-full-findings-dir.json").mkdir()
        assert latest_files(str(tmp_path), "*-full-findings-*.json", n=5) == [keep]

    def test_before_keeps_one_second_of_slack(self, tmp_path):
        old = self._touch(tmp_path, "f-old.json", 10)
        self._touch(tmp_path, "f-edge.json", 1)  # mtime == before - 1: excluded
        self._touch(tmp_path, "f-new.json", 0.5)
        assert latest_files(str(tmp_path), "f-*.json", n=5, before=self.NOW) == [old]
        assert len(latest_files(str(tmp_path), "f-*.json", n=5)) == 3

    def test_missing_directory_is_empty(self, tmp_path):
        assert latest_files(str(tmp_path / "missing"), "*") == []
