"""Tests for src/common/file_utils.py — read/write helpers."""

import csv

import pytest

from src.common.exceptions import FileProcessingError
from src.common.file_utils import read_csv, read_json, write_csv, write_csv_stream, write_json


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
