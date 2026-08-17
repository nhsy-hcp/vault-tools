"""Tests for src/common/config.py — GlobalConfig, the only configuration the CLI uses."""

import pytest

from src.common.exceptions import ConfigurationError

# ---------------------------------------------------------------------------
# GlobalConfig
# ---------------------------------------------------------------------------


class TestGlobalConfig:
    def test_defaults(self):
        from src.common.config import GlobalConfig

        cfg = GlobalConfig()
        assert cfg.output_dir == "outputs"
        assert cfg.debug is False

    def test_from_environment_defaults(self, monkeypatch):
        from src.common.config import GlobalConfig

        monkeypatch.delenv("VAULT_TOOLS_OUTPUT_DIR", raising=False)
        monkeypatch.delenv("VAULT_TOOLS_DEBUG", raising=False)
        cfg = GlobalConfig.from_environment()
        assert cfg.output_dir == "outputs"
        assert cfg.debug is False

    def test_from_environment_custom(self, monkeypatch):
        from src.common.config import GlobalConfig

        monkeypatch.setenv("VAULT_TOOLS_OUTPUT_DIR", "custom-out")
        monkeypatch.setenv("VAULT_TOOLS_DEBUG", "true")
        cfg = GlobalConfig.from_environment()
        assert cfg.output_dir == "custom-out"
        assert cfg.debug is True


class TestGlobalConfigOutputDirOverride:
    """The CLI --output-dir must go through validation, not around it.

    Regression tests: main.py used to assign global_config.output_dir after
    construction, so __post_init__'s create-and-check never saw the CLI value.
    A bad path then survived until report-write time, after a full namespace
    traversal had already run.
    """

    def test_override_is_validated_and_created(self, tmp_path):
        from src.common.config import GlobalConfig

        target = tmp_path / "nested" / "reports"
        cfg = GlobalConfig.from_environment(output_dir=str(target))

        assert cfg.output_dir == str(target)
        assert target.is_dir(), "override directory was not created"

    def test_override_rejects_uncreatable_path(self, tmp_path):
        from src.common.config import GlobalConfig

        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")

        with pytest.raises(ConfigurationError, match="Cannot create output directory"):
            GlobalConfig.from_environment(output_dir=str(blocker / "sub"))

    def test_override_rejects_unwritable_directory(self, tmp_path):
        import os

        from src.common.config import GlobalConfig

        readonly = tmp_path / "readonly"
        readonly.mkdir()
        readonly.chmod(0o500)
        try:
            if os.access(str(readonly), os.W_OK):  # running as root
                pytest.skip("cannot exercise unwritable path as root")
            with pytest.raises(ConfigurationError, match="not writable"):
                GlobalConfig.from_environment(output_dir=str(readonly))
        finally:
            readonly.chmod(0o700)

    def test_env_var_used_when_no_override(self, tmp_path, monkeypatch):
        from src.common.config import GlobalConfig

        monkeypatch.setenv("VAULT_TOOLS_OUTPUT_DIR", str(tmp_path / "from-env"))
        cfg = GlobalConfig.from_environment()
        assert cfg.output_dir == str(tmp_path / "from-env")

    def test_override_takes_precedence_over_env_var(self, tmp_path, monkeypatch):
        from src.common.config import GlobalConfig

        monkeypatch.setenv("VAULT_TOOLS_OUTPUT_DIR", str(tmp_path / "from-env"))
        cfg = GlobalConfig.from_environment(output_dir=str(tmp_path / "from-cli"))
        assert cfg.output_dir == str(tmp_path / "from-cli")
