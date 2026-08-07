"""Tests for main.py argument parsing.

Global flags (--debug, --json-logs, --output-dir) live on a shared parent parser
that is attached to both the top-level parser and every subparser, so they are
accepted in either position. That arrangement has a well-known trap: the
subparser parses last, so an ordinary default would overwrite a value supplied
before the subcommand. These tests pin both positions.
"""

import pytest

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
        args = _build_parser().parse_args(["namespace-audit", "-w", "8", "-n", "team-a/"])
        assert args.workers == 8
        assert args.namespace == "team-a/"


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
