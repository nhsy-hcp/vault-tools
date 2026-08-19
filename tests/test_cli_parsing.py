"""Tests for main.py argument parsing.

Global flags (--debug, --json-logs, --output-dir) live on a shared parent parser
that is attached to both the top-level parser and every subparser, so they are
accepted in either position. That arrangement has a well-known trap: the
subparser parses last, so an ordinary default would overwrite a value supplied
before the subcommand. These tests pin both positions.
"""

import tomllib
from pathlib import Path

import pytest

import main
from main import build_parser as _build_parser


class TestGlobalFlagPositions:
    def test_output_dir_before_subcommand(self):
        args = _build_parser().parse_args(["--output-dir", "/tmp/x", "namespace-audit"])
        assert getattr(args, "output_dir", None) == "/tmp/x"

    def test_output_dir_after_subcommand(self):
        """Previously failed with 'unrecognized arguments'."""
        args = _build_parser().parse_args(["namespace-audit", "--output-dir", "/tmp/x"])
        assert getattr(args, "output_dir", None) == "/tmp/x"

    def test_output_dir_absent_is_unset(self):
        args = _build_parser().parse_args(["namespace-audit"])
        assert getattr(args, "output_dir", None) is None

    @pytest.mark.parametrize("flag,attr", [("--debug", "debug"), ("--json-logs", "json_logs")])
    @pytest.mark.parametrize("position", ["before", "after"])
    def test_boolean_flags_in_both_positions(self, flag, attr, position):
        argv = [flag, "namespace-audit"] if position == "before" else ["namespace-audit", flag]
        args = _build_parser().parse_args(argv)
        assert getattr(args, attr, False) is True

    def test_subcommand_options_still_parse(self):
        args = _build_parser().parse_args(["namespace-audit", "-w", "8"])
        assert args.workers == 8

    @pytest.mark.parametrize(
        "argv",
        [["namespace-audit"], ["all", "-s", "2026-01-01", "-e", "2026-01-31"]],
        ids=["namespace-audit", "all"],
    )
    def test_no_sentinel_defaults_to_collecting(self, argv):
        assert _build_parser().parse_args(argv).no_sentinel is False

    @pytest.mark.parametrize(
        "argv",
        [["namespace-audit"], ["all", "-s", "2026-01-01", "-e", "2026-01-31"]],
        ids=["namespace-audit", "all"],
    )
    def test_no_sentinel_parses_on_both_subcommands(self, argv):
        """Both constructions of NamespaceAuditor read this flag."""
        assert _build_parser().parse_args([*argv, "--no-sentinel"]).no_sentinel is True

    @pytest.mark.parametrize("argv", [["namespace-audit", "-n", "team-a/"], ["all", "-s", "2026-01-01", "-e", "2026-01-31", "-n", "team-a/"]])
    def test_namespace_flag_is_gone(self, argv):
        """--namespace was removed: it only ever scoped the audit, never the exports."""
        with pytest.raises(SystemExit):
            _build_parser().parse_args(argv)


class TestAllSubcommandsAcceptGlobalFlags:
    @pytest.mark.parametrize(
        "argv",
        [
            ["namespace-audit"],
            ["activity-export", "-s", "2026-01-01", "-e", "2026-01-31"],
            ["entity-export", "-s", "2026-01-01", "-e", "2026-01-31"],
            ["all", "-s", "2026-01-01", "-e", "2026-01-31"],
        ],
        ids=["namespace-audit", "activity-export", "entity-export", "all"],
    )
    def test_output_dir_accepted_after_every_subcommand(self, argv):
        args = _build_parser().parse_args([*argv, "--output-dir", "/tmp/x"])
        assert getattr(args, "output_dir", None) == "/tmp/x"


def _manifest_version() -> str:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]


class TestVersionFlag:
    def test_version_prints_and_exits_cleanly(self, capsys):
        """`--version` must win over the required subcommand, not error out.

        Asserted against pyproject.toml rather than main.__version__: the
        parser's version string is interpolated from that same attribute, so
        comparing the two only proves f-strings work.
        """
        with pytest.raises(SystemExit) as exc:
            _build_parser().parse_args(["--version"])
        assert exc.value.code == 0
        assert capsys.readouterr().out.strip() == f"vault-tools {_manifest_version()}"

    def test_fallback_version_matches_pyproject(self):
        """The PEP 723 script path uses the literal; keep it in step with the manifest."""
        assert _manifest_version() == main._FALLBACK_VERSION
