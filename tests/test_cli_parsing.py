"""Tests for main.py argument parsing.

Global flags (--debug, --json-logs, --output-dir) live on a shared parent parser
that is attached to both the top-level parser and every subparser, so they are
accepted in either position. That arrangement has a well-known trap: the
subparser parses last, so an ordinary default would overwrite a value supplied
before the subcommand. These tests pin both positions.
"""

import argparse
import json
import tomllib
from datetime import date
from pathlib import Path
from unittest.mock import Mock, patch

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

    @pytest.mark.parametrize("argv", [["namespace-audit"], ["full-audit"]], ids=["namespace-audit", "full-audit"])
    def test_no_sentinel_defaults_to_collecting(self, argv):
        assert _build_parser().parse_args(argv).no_sentinel is False

    @pytest.mark.parametrize("argv", [["namespace-audit"], ["full-audit"]], ids=["namespace-audit", "full-audit"])
    def test_no_sentinel_parses_on_both_subcommands(self, argv):
        """Both constructions of NamespaceAuditor read this flag."""
        assert _build_parser().parse_args([*argv, "--no-sentinel"]).no_sentinel is True

    @pytest.mark.parametrize("argv", [["namespace-audit", "-n", "team-a/"], ["full-audit", "-n", "team-a/"]])
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
            ["full-audit"],
            ["cluster-audit"],
            ["identity-audit"],
            ["diff"],
        ],
        ids=["namespace-audit", "activity-export", "entity-export", "full-audit", "cluster-audit", "identity-audit", "diff"],
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


class TestFindingsGatingFlags:
    def test_defaults_do_not_gate(self):
        args = _build_parser().parse_args(["namespace-audit"])
        assert (args.fail_on, args.fail_on_gaps) == (None, False)

    def test_fail_on_takes_a_severity(self):
        args = _build_parser().parse_args(["namespace-audit", "--fail-on", "medium", "--fail-on-gaps"])
        assert (args.fail_on, args.fail_on_gaps) == ("medium", True)

    def test_fail_on_rejects_unknown_severity(self):
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["namespace-audit", "--fail-on", "critical-ish"])

    def test_diff_takes_two_files(self):
        args = _build_parser().parse_args(["diff", "old.json", "new.json", "--output-dir", "/tmp/x"])
        assert (args.old, args.new, args.output_dir) == ("old.json", "new.json", "/tmp/x")


def _findings_doc(findings, complete=True):
    return {"findings": findings, "coverage": {"complete": complete}, "run": {}}


class TestMainExitCodes:
    """main() end to end with the auditor stubbed, so no Vault is needed."""

    def _run(self, monkeypatch, tmp_path, argv, document):
        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")
        monkeypatch.setattr("sys.argv", ["main.py", *argv, "--output-dir", str(tmp_path)])
        with patch("main.NamespaceAuditor") as auditor_cls:
            auditor_cls.return_value.audit_cluster.return_value = document
            with pytest.raises(SystemExit) as exc:
                main.main()
            return exc.value.code

    def _run_ok(self, monkeypatch, tmp_path, argv, document):
        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")
        monkeypatch.setattr("sys.argv", ["main.py", *argv, "--output-dir", str(tmp_path)])
        with patch("main.NamespaceAuditor") as auditor_cls:
            auditor_cls.return_value.audit_cluster.return_value = document
            main.main()

    def test_findings_at_threshold_exit_3(self, monkeypatch, tmp_path):
        doc = _findings_doc([{"severity": "low"}])
        assert self._run(monkeypatch, tmp_path, ["namespace-audit", "--fail-on", "low"], doc) == 3

    def test_gaps_exit_2(self, monkeypatch, tmp_path):
        doc = _findings_doc([], complete=False)
        assert self._run(monkeypatch, tmp_path, ["namespace-audit", "--fail-on-gaps"], doc) == 2

    def test_failed_audit_exits_1(self, monkeypatch, tmp_path):
        assert self._run(monkeypatch, tmp_path, ["namespace-audit"], None) == 1

    def test_clean_run_without_flags_exits_normally(self, monkeypatch, tmp_path):
        self._run_ok(monkeypatch, tmp_path, ["namespace-audit"], _findings_doc([{"severity": "high"}]))


class TestDiffCommand:
    def _write(self, path, findings):
        path.write_text(json.dumps(_findings_doc(findings)))
        return str(path)

    def test_diff_runs_without_vault_credentials(self, monkeypatch, tmp_path):
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        item = {"fingerprint": "a" * 16, "rule_id": "VT-NS-001", "severity": "info", "namespace": "/", "object": {}, "detail": "d", "evidence": {}}
        old = self._write(tmp_path / "old.json", [])
        new = self._write(tmp_path / "new.json", [item])
        monkeypatch.setattr("sys.argv", ["main.py", "diff", old, new, "--output-dir", str(tmp_path)])

        main.main()

        [written] = list(tmp_path.glob("diff-*.json"))
        assert json.loads(written.read_text())["summary"]["new"] == 1

    def test_diff_rejects_a_non_findings_file(self, monkeypatch, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{}")
        monkeypatch.setattr("sys.argv", ["main.py", "diff", str(bad), str(bad), "--output-dir", str(tmp_path)])
        with pytest.raises(SystemExit) as exc:
            main.main()
        assert exc.value.code == 1


class TestClusterAuditCommand:
    def test_parses_with_gating_flags(self):
        args = _build_parser().parse_args(["cluster-audit", "--fail-on", "medium", "--fail-on-gaps", "--output-dir", "/tmp/x"])
        assert (args.command, args.fail_on, args.fail_on_gaps, args.output_dir) == ("cluster-audit", "medium", True, "/tmp/x")

    def _run(self, monkeypatch, tmp_path, argv, document):
        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")
        monkeypatch.setattr("sys.argv", ["main.py", *argv, "--output-dir", str(tmp_path)])
        with patch("main.run_cluster_audit", return_value=document):
            with pytest.raises(SystemExit) as exc:
                main.main()
            return exc.value.code

    def test_findings_gate_exit_3(self, monkeypatch, tmp_path):
        assert self._run(monkeypatch, tmp_path, ["cluster-audit", "--fail-on", "medium"], _findings_doc([{"severity": "medium"}])) == 3

    def test_failed_run_exits_1(self, monkeypatch, tmp_path):
        assert self._run(monkeypatch, tmp_path, ["cluster-audit"], None) == 1


class TestNamesOnlyFlag:
    """The token decides what is read; --names-only is the only opt-out."""

    @pytest.mark.parametrize("command", ["namespace-audit", "full-audit"])
    def test_off_by_default(self, command):
        assert _build_parser().parse_args([command]).names_only is False

    @pytest.mark.parametrize("command", ["namespace-audit", "full-audit"])
    def test_opt_out(self, command):
        assert _build_parser().parse_args([command, "--names-only"]).names_only is True

    def test_acl_bodies_flag_is_gone(self):
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["namespace-audit", "--acl-bodies"])


class TestIdentityAuditCommand:
    def test_parses(self):
        args = _build_parser().parse_args(["identity-audit", "-w", "2", "--list", "--fail-on", "low"])
        assert (args.command, args.workers, args.list, args.fail_on) == ("identity-audit", 2, True, "low")

    def test_list_off_by_default(self):
        assert _build_parser().parse_args(["identity-audit"]).list is False

    def test_list_entities_is_an_alias_of_list(self):
        """Spelled the same as full-audit's flag."""
        assert _build_parser().parse_args(["identity-audit", "--list-entities"]).list is True

    def test_has_no_policy_options(self):
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["identity-audit", "--names-only"])


class TestActivityExportGating:
    def test_parses_gating_flags(self):
        args = _build_parser().parse_args(["activity-export", "-s", "2026-01-01", "-e", "2026-01-31", "--fail-on", "low"])
        assert args.fail_on == "low"

    def test_findings_gate_exit_3(self, monkeypatch, tmp_path):
        from src.activity_export.main import ActivityExportResult
        from src.common.vault_client import ConnectionInfo

        monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")
        monkeypatch.setattr("sys.argv", ["main.py", "activity-export", "-s", "2026-01-01", "-e", "2026-01-31", "--fail-on", "low", "--output-dir", str(tmp_path)])
        result = ActivityExportResult([], [], _findings_doc([{"severity": "low"}]))
        with (
            patch("main.VaultClient.validate_connection", return_value=ConnectionInfo("c", "1.20.0+ent", True, "id")),
            patch("main.run_activity_export", return_value=result) as run,
            pytest.raises(SystemExit) as exc,
        ):
            main.main()
        assert exc.value.code == 3
        assert run.call_args.kwargs["is_enterprise"] is True


class TestCreateVaultClientTls:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        monkeypatch.delenv("VAULT_SKIP_VERIFY", raising=False)
        monkeypatch.delenv("VAULT_CACERT", raising=False)

    def test_cacert_is_used(self, monkeypatch, tmp_path):
        ca = tmp_path / "ca.pem"
        ca.write_text("pem")
        monkeypatch.setenv("VAULT_CACERT", str(ca))
        client = main.create_vault_client(Mock())
        assert client.verify == str(ca)

    def test_missing_cacert_exits_1(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setenv("VAULT_CACERT", str(tmp_path / "missing.pem"))
        with pytest.raises(SystemExit) as exc:
            main.create_vault_client(Mock())
        assert exc.value.code == 1
        assert "VAULT_CACERT file not found" in capsys.readouterr().err

    def test_skip_verify_wins_over_cacert(self, monkeypatch, tmp_path):
        monkeypatch.setenv("VAULT_SKIP_VERIFY", "true")
        monkeypatch.setenv("VAULT_CACERT", str(tmp_path / "missing.pem"))
        assert main.create_vault_client(Mock()).verify is False


def _env(monkeypatch, tmp_path, argv):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")
    monkeypatch.setattr("sys.argv", ["main.py", *argv, "--output-dir", str(tmp_path)])


def _subcommands(parser: argparse.ArgumentParser) -> list[str]:
    [action] = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    return list(action.choices)


class TestAllSubcommandIsGone:
    """`all` was a worse subset of full-audit and was removed."""

    def test_rejected_as_invalid_choice(self, capsys):
        with pytest.raises(SystemExit) as exc:
            _build_parser().parse_args(["all", "-s", "2026-01-01", "-e", "2026-01-31"])
        assert exc.value.code == 2
        assert "invalid choice: 'all'" in capsys.readouterr().err

    def test_not_in_commands(self):
        assert "all" not in main.COMMANDS


class TestGroupedHelp:
    def test_full_audit_is_registered_first(self):
        assert _subcommands(_build_parser())[0] == "full-audit"

    def test_help_lists_groups(self, capsys):
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["--help"])
        out = capsys.readouterr().out
        assert out.index("Audits:") < out.index("Exports:") < out.index("Utilities:")
        assert "(recommended)" in out


class TestOptionalExportWindow:
    @pytest.mark.parametrize("command", ["activity-export", "entity-export", "full-audit"])
    def test_parses_without_dates(self, command):
        args = _build_parser().parse_args([command])
        assert (args.start_date, args.end_date) == (None, None)

    @pytest.mark.parametrize("dates", [("2026-01-01", None), (None, "2026-01-31")])
    def test_resolve_window_rejects_half_a_window(self, dates, capsys):
        args = argparse.Namespace(start_date=dates[0], end_date=dates[1])
        with pytest.raises(SystemExit) as exc:
            main.resolve_window(args, Mock())
        assert exc.value.code == 1
        assert "pass both --start-date and --end-date" in capsys.readouterr().err

    def test_resolve_window_keeps_given_dates(self, capsys):
        args = argparse.Namespace(start_date="2026-01-01", end_date="2026-01-31")
        assert main.resolve_window(args, Mock()) == ("2026-01-01", "2026-01-31")
        assert "Window:" not in capsys.readouterr().out

    def test_resolve_window_validates_given_dates(self):
        args = argparse.Namespace(start_date="2026-02-01", end_date="2026-01-31")
        with pytest.raises(SystemExit) as exc:
            main.resolve_window(args, Mock())
        assert exc.value.code == 1

    def test_resolve_window_defaults_to_last_12_months_and_prints_it(self, capsys):
        args = argparse.Namespace(start_date=None, end_date=None)
        with patch("main.date") as fake_date:
            fake_date.today.return_value = date(2026, 10, 8)
            assert main.resolve_window(args, Mock()) == ("2025-11-01", "2026-10-08")
        assert "Window: 2025-11-01 → 2026-10-08 (default: last 12 calendar months)" in capsys.readouterr().out

    @pytest.mark.parametrize("command,target", [("activity-export", "main.run_activity_export"), ("entity-export", "main.run_entity_export")])
    def test_export_without_dates_uses_default_window(self, command, target, monkeypatch, tmp_path):
        from src.activity_export.main import ActivityExportResult
        from src.common.vault_client import ConnectionInfo

        _env(monkeypatch, tmp_path, [command])
        result = ActivityExportResult([], [], _findings_doc([]))
        with (
            patch("main.date") as fake_date,
            patch("main.VaultClient.validate_connection", return_value=ConnectionInfo("c", "1.20.0+ent", True, "id")),
            patch(target, return_value=result) as run,
        ):
            fake_date.today.return_value = date(2026, 10, 8)
            main.main()
        assert run.call_args.args[1:3] == ("2025-11-01", "2026-10-08")


class TestFullAuditStepSelection:
    def test_skip_and_only_default_to_none(self):
        args = _build_parser().parse_args(["full-audit"])
        assert (args.skip, args.only) == (None, None)

    def test_skip_is_repeatable(self):
        args = _build_parser().parse_args(["full-audit", "--skip", "entity-export", "--skip", "identity-audit"])
        assert args.skip == ["entity-export", "identity-audit"]

    def test_skip_and_only_are_mutually_exclusive(self):
        with pytest.raises(SystemExit) as exc:
            _build_parser().parse_args(["full-audit", "--skip", "entity-export", "--only", "namespace-audit"])
        assert exc.value.code == 2

    def test_cluster_audit_cannot_be_skipped(self):
        """It supplies the cluster name and node state for every other step."""
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["full-audit", "--skip", "cluster-audit"])

    @pytest.mark.parametrize(
        "flags,expected",
        [
            ([], frozenset()),
            (["--skip", "entity-export"], frozenset({"entity-export"})),
            (["--only", "namespace-audit"], frozenset({"identity-audit", "activity-export", "entity-export"})),
            (["--only", "namespace-audit", "--only", "entity-export"], frozenset({"identity-audit", "activity-export"})),
        ],
        ids=["none", "skip", "only", "only-twice"],
    )
    def test_skip_set_passed_to_run_full_audit(self, flags, expected, monkeypatch, tmp_path):
        _env(monkeypatch, tmp_path, ["full-audit", "-s", "2026-01-01", "-e", "2026-01-31", *flags])
        with patch("main.run_full_audit", return_value=_findings_doc([])) as run:
            main.main()
        kwargs = run.call_args.kwargs
        assert kwargs["skip"] == expected
        assert (kwargs["start_date"], kwargs["end_date"]) == ("2026-01-01", "2026-01-31")

    def test_failed_run_exits_1(self, monkeypatch, tmp_path):
        _env(monkeypatch, tmp_path, ["full-audit"])
        with patch("main.run_full_audit", return_value=None), pytest.raises(SystemExit) as exc:
            main.main()
        assert exc.value.code == 1


class TestDiffArguments:
    def test_zero_args_parse(self):
        args = _build_parser().parse_args(["diff"])
        assert (args.old, args.new) == (None, None)

    def test_one_arg_exits_1(self, monkeypatch, tmp_path, capsys):
        """run_diff owns the both-or-neither rule; the CLI reports its error."""
        monkeypatch.setattr("sys.argv", ["main.py", "diff", "old.json", "--output-dir", str(tmp_path)])
        with pytest.raises(SystemExit) as exc:
            main.main()
        assert exc.value.code == 1
        assert "both OLD and NEW, or neither" in capsys.readouterr().err

    def test_zero_args_passes_none_to_run_diff(self, monkeypatch, tmp_path):
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        monkeypatch.setattr("sys.argv", ["main.py", "diff", "--output-dir", str(tmp_path)])
        with patch("main.run_diff") as run:
            main.main()
        run.assert_called_once_with(None, None, str(tmp_path))


class TestCommandDispatch:
    def test_commands_cover_every_vault_subcommand(self):
        assert set(main.COMMANDS) == {"full-audit", "namespace-audit", "cluster-audit", "identity-audit", "activity-export", "entity-export"}

    def test_parser_choices_are_commands_plus_diff(self):
        assert set(_subcommands(_build_parser())) == set(main.COMMANDS) | {"diff"}

    @pytest.mark.parametrize(
        "argv",
        [["full-audit"], ["namespace-audit"], ["cluster-audit"], ["identity-audit"], ["activity-export"], ["entity-export"]],
        ids=lambda argv: argv[0],
    )
    def test_main_routes_to_the_handler(self, argv, monkeypatch, tmp_path):
        _env(monkeypatch, tmp_path, argv)
        handler = Mock(return_value=0)
        with patch.dict(main.COMMANDS, {argv[0]: handler}):
            main.main()
        handler.assert_called_once()
        args, vault_client, config, _logger = handler.call_args.args
        assert args.command == argv[0]
        assert isinstance(vault_client, main.VaultClient)
        assert config.output_dir == str(tmp_path)

    def test_handler_exit_code_becomes_the_process_exit_code(self, monkeypatch, tmp_path):
        _env(monkeypatch, tmp_path, ["cluster-audit"])
        with patch.dict(main.COMMANDS, {"cluster-audit": Mock(return_value=3)}), pytest.raises(SystemExit) as exc:
            main.main()
        assert exc.value.code == 3

    def test_identity_handler_passes_list(self, monkeypatch, tmp_path):
        _env(monkeypatch, tmp_path, ["identity-audit", "--list-entities", "-w", "2"])
        with patch("main.run_identity_audit", return_value=_findings_doc([])) as run:
            main.main()
        assert run.call_args.kwargs == {"workers": 2, "include_list": True}
