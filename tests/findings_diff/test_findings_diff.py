"""`diff`: explicit paths, and auto-picking the two newest full-audit findings files."""

import json
import os
import re
import time

import pytest
from rich.console import Console

from src.common.exceptions import FileProcessingError, VaultToolsError
from src.findings_diff.main import run_diff

ITEM = {"fingerprint": "a" * 16, "rule_id": "VT-NS-001", "severity": "info", "namespace": "/", "object": {}, "detail": "d", "evidence": {}}


def _write(path, findings, age=0):
    path.write_text(json.dumps({"findings": findings}))
    stamp = time.time() - age
    os.utime(path, (stamp, stamp))
    return str(path)


def _console():
    return Console(record=True, width=200)


def _diff_summary(path):
    return json.loads(open(path).read())["summary"]


def test_explicit_paths(tmp_path):
    old = _write(tmp_path / "old.json", [])
    new = _write(tmp_path / "new.json", [ITEM])
    out = run_diff(old, new, str(tmp_path), console=Console(quiet=True))
    assert _diff_summary(out)["new"] == 1


def test_no_paths_compares_the_two_newest_full_findings(tmp_path):
    _write(tmp_path / "c-full-findings-20260901.json", [ITEM, {**ITEM, "fingerprint": "b" * 16}], age=300)
    older = _write(tmp_path / "c-full-findings-20261001.json", [], age=200)
    newest = _write(tmp_path / "c-full-findings-20261008.json", [ITEM], age=100)
    # Newer, but not a full-audit file: never picked.
    _write(tmp_path / "c-namespace-findings-20261008.json", [], age=0)
    console = _console()

    out = run_diff(None, None, str(tmp_path), console=console)

    assert _diff_summary(out) == {"new": 1, "resolved": 0, "unchanged": 0, "evidence_changed": 0}
    text = console.export_text()
    assert f"old: {os.path.basename(older)}" in text
    assert f"new: {os.path.basename(newest)}" in text


def test_no_paths_pairs_only_the_newest_files_cluster(tmp_path):
    older = _write(tmp_path / "prod-full-findings-20261001.json", [], age=300)
    # Another cluster's run sits between the two: never paired with prod's.
    _write(tmp_path / "dev-full-findings-20261005.json", [ITEM], age=200)
    newest = _write(tmp_path / "prod-full-findings-20261008.json", [ITEM], age=100)
    console = _console()

    run_diff(None, None, str(tmp_path), console=console)

    text = console.export_text()
    assert f"old: {os.path.basename(older)}" in text
    assert f"new: {os.path.basename(newest)}" in text


def test_newest_cluster_with_one_run_is_an_error(tmp_path):
    _write(tmp_path / "dev-full-findings-20261001.json", [], age=300)
    _write(tmp_path / "dev-full-findings-20261002.json", [], age=200)
    _write(tmp_path / "prod-full-findings-20261008.json", [], age=100)
    with pytest.raises(FileProcessingError, match="found 1 full-findings file for this cluster"):
        run_diff(None, None, str(tmp_path), console=Console(quiet=True))


@pytest.mark.parametrize("count", [0, 1])
def test_fewer_than_two_files_is_an_error(tmp_path, count):
    for i in range(count):
        _write(tmp_path / f"c-full-findings-2026100{i}.json", [])
    with pytest.raises(FileProcessingError, match=rf"found {count} full-findings file.* for this cluster in {re.escape(str(tmp_path))}\. Pass OLD and NEW explicitly"):
        run_diff(None, None, str(tmp_path), console=Console(quiet=True))
    assert not list(tmp_path.glob("diff-*.json"))


def test_missing_output_dir_is_an_error(tmp_path):
    with pytest.raises(FileProcessingError, match="found 0"):
        run_diff(None, None, str(tmp_path / "missing"), console=Console(quiet=True))


@pytest.mark.parametrize("which", ["old", "new"])
def test_only_one_path_is_an_error(tmp_path, which):
    path = _write(tmp_path / "c-full-findings-20261001.json", [])
    _write(tmp_path / "c-full-findings-20261008.json", [])
    args = (path, None) if which == "old" else (None, path)
    with pytest.raises(VaultToolsError, match="both OLD and NEW, or neither"):
        run_diff(*args, str(tmp_path), console=Console(quiet=True))
