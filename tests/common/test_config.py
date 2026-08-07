"""Tests for src/common/config.py — all dataclass configurations."""

import pytest

from src.common.exceptions import ConfigurationError

# ---------------------------------------------------------------------------
# VaultConfig
# ---------------------------------------------------------------------------


class TestVaultConfig:
    def test_valid_config(self):
        from src.common.config import VaultConfig

        cfg = VaultConfig(vault_addr="https://vault.example.com", vault_token="s.test")
        assert cfg.vault_addr == "https://vault.example.com"
        assert cfg.vault_token == "s.test"
        assert cfg.vault_skip_verify is False

    def test_missing_vault_addr_raises(self):
        from src.common.config import VaultConfig

        with pytest.raises(ConfigurationError, match="VAULT_ADDR"):
            VaultConfig(vault_addr="", vault_token="s.test")

    def test_missing_vault_token_raises(self):
        from src.common.config import VaultConfig

        with pytest.raises(ConfigurationError, match="VAULT_TOKEN"):
            VaultConfig(vault_addr="https://vault.example.com", vault_token="")

    def test_skip_verify_flag(self):
        from src.common.config import VaultConfig

        cfg = VaultConfig(
            vault_addr="https://vault.example.com",
            vault_token="s.test",
            vault_skip_verify=True,
        )
        assert cfg.vault_skip_verify is True


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


# ---------------------------------------------------------------------------
# NamespaceAuditConfig
# ---------------------------------------------------------------------------


class TestNamespaceAuditConfig:
    def _valid_kwargs(self, **overrides):
        base = {"vault_addr": "https://vault.example.com", "vault_token": "s.test"}
        base.update(overrides)
        return base

    def test_valid_config(self):
        from src.common.config import NamespaceAuditConfig

        cfg = NamespaceAuditConfig(**self._valid_kwargs())
        assert cfg.worker_threads == 4
        assert cfg.rate_limit_batch_size == 100

    def test_namespace_path_auto_suffixed(self):
        from src.common.config import NamespaceAuditConfig

        cfg = NamespaceAuditConfig(**self._valid_kwargs(namespace_path="team-a"))
        assert cfg.namespace_path == "team-a/"

    def test_namespace_path_already_suffixed(self):
        from src.common.config import NamespaceAuditConfig

        cfg = NamespaceAuditConfig(**self._valid_kwargs(namespace_path="team-a/"))
        assert cfg.namespace_path == "team-a/"

    def test_zero_worker_threads_raises(self):
        from src.common.config import NamespaceAuditConfig

        with pytest.raises(ConfigurationError, match="Worker threads"):
            NamespaceAuditConfig(**self._valid_kwargs(worker_threads=0))

    def test_zero_batch_size_raises(self):
        from src.common.config import NamespaceAuditConfig

        with pytest.raises(ConfigurationError, match="Rate limit batch size"):
            NamespaceAuditConfig(**self._valid_kwargs(rate_limit_batch_size=0))

    def test_zero_timeout_raises(self):
        from src.common.config import NamespaceAuditConfig

        with pytest.raises(ConfigurationError, match="HVAC timeout"):
            NamespaceAuditConfig(**self._valid_kwargs(hvac_timeout=0))

    def test_from_environment_defaults(self, monkeypatch):
        from src.common.config import NamespaceAuditConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        for var in [
            "VAULT_SKIP_VERIFY",
            "VAULT_TOOLS_WORKERS",
            "VAULT_TOOLS_RATE_LIMIT_BATCH",
            "VAULT_TOOLS_RATE_LIMIT_SLEEP",
            "VAULT_TOOLS_TIMEOUT",
            "VAULT_TOOLS_NAMESPACE",
            "VAULT_TOOLS_NO_RATE_LIMIT",
        ]:
            monkeypatch.delenv(var, raising=False)

        cfg = NamespaceAuditConfig.from_environment()
        assert cfg.worker_threads == 4
        assert cfg.rate_limit_batch_size == 100
        assert cfg.rate_limit_sleep_seconds == 3
        assert cfg.hvac_timeout == 30

    def test_from_environment_bad_workers_raises(self, monkeypatch):
        from src.common.config import NamespaceAuditConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        monkeypatch.setenv("VAULT_TOOLS_WORKERS", "not-an-int")
        with pytest.raises(ConfigurationError, match="VAULT_TOOLS_WORKERS"):
            NamespaceAuditConfig.from_environment()

    def test_from_environment_bad_batch_raises(self, monkeypatch):
        from src.common.config import NamespaceAuditConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        monkeypatch.setenv("VAULT_TOOLS_WORKERS", "4")
        monkeypatch.setenv("VAULT_TOOLS_RATE_LIMIT_BATCH", "bad")
        with pytest.raises(ConfigurationError, match="VAULT_TOOLS_RATE_LIMIT_BATCH"):
            NamespaceAuditConfig.from_environment()

    def test_from_environment_bad_sleep_raises(self, monkeypatch):
        from src.common.config import NamespaceAuditConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        monkeypatch.setenv("VAULT_TOOLS_WORKERS", "4")
        monkeypatch.setenv("VAULT_TOOLS_RATE_LIMIT_BATCH", "100")
        monkeypatch.setenv("VAULT_TOOLS_RATE_LIMIT_SLEEP", "bad")
        with pytest.raises(ConfigurationError, match="VAULT_TOOLS_RATE_LIMIT_SLEEP"):
            NamespaceAuditConfig.from_environment()

    def test_from_environment_bad_timeout_raises(self, monkeypatch):
        from src.common.config import NamespaceAuditConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        monkeypatch.setenv("VAULT_TOOLS_WORKERS", "4")
        monkeypatch.setenv("VAULT_TOOLS_RATE_LIMIT_BATCH", "100")
        monkeypatch.setenv("VAULT_TOOLS_RATE_LIMIT_SLEEP", "3")
        monkeypatch.setenv("VAULT_TOOLS_TIMEOUT", "bad")
        with pytest.raises(ConfigurationError, match="VAULT_TOOLS_TIMEOUT"):
            NamespaceAuditConfig.from_environment()

    def test_from_environment_with_override(self, monkeypatch):
        from src.common.config import NamespaceAuditConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        for var in ["VAULT_TOOLS_WORKERS", "VAULT_TOOLS_RATE_LIMIT_BATCH", "VAULT_TOOLS_RATE_LIMIT_SLEEP", "VAULT_TOOLS_TIMEOUT"]:
            monkeypatch.delenv(var, raising=False)

        cfg = NamespaceAuditConfig.from_environment(worker_threads=8)
        assert cfg.worker_threads == 8

    def test_from_environment_skip_verify(self, monkeypatch):
        from src.common.config import NamespaceAuditConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        monkeypatch.setenv("VAULT_SKIP_VERIFY", "true")
        for var in ["VAULT_TOOLS_WORKERS", "VAULT_TOOLS_RATE_LIMIT_BATCH", "VAULT_TOOLS_RATE_LIMIT_SLEEP", "VAULT_TOOLS_TIMEOUT"]:
            monkeypatch.delenv(var, raising=False)

        cfg = NamespaceAuditConfig.from_environment()
        assert cfg.vault_skip_verify is True

    def test_from_environment_rate_limit_disable(self, monkeypatch):
        from src.common.config import NamespaceAuditConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        monkeypatch.setenv("VAULT_TOOLS_NO_RATE_LIMIT", "true")
        for var in ["VAULT_TOOLS_WORKERS", "VAULT_TOOLS_RATE_LIMIT_BATCH", "VAULT_TOOLS_RATE_LIMIT_SLEEP", "VAULT_TOOLS_TIMEOUT"]:
            monkeypatch.delenv(var, raising=False)

        cfg = NamespaceAuditConfig.from_environment()
        assert cfg.rate_limit_disable is True


# ---------------------------------------------------------------------------
# ActivityExportConfig / EntityExportConfig
# ---------------------------------------------------------------------------


class TestActivityExportConfig:
    def _valid_kwargs(self, **overrides):
        base = {
            "vault_addr": "https://vault.example.com",
            "vault_token": "s.test",
            "start_date": "2024-01-01",
            "end_date": "2024-01-31",
            "cluster_name": "my-cluster",
        }
        base.update(overrides)
        return base

    def test_valid_config(self):
        from src.common.config import ActivityExportConfig

        cfg = ActivityExportConfig(**self._valid_kwargs())
        assert cfg.start_date == "2024-01-01"
        assert cfg.cluster_name == "my-cluster"

    def test_missing_start_date_raises(self):
        from src.common.config import ActivityExportConfig

        with pytest.raises(ConfigurationError, match="Start date"):
            ActivityExportConfig(**self._valid_kwargs(start_date=""))

    def test_missing_end_date_raises(self):
        from src.common.config import ActivityExportConfig

        with pytest.raises(ConfigurationError, match="End date"):
            ActivityExportConfig(**self._valid_kwargs(end_date=""))

    def test_missing_cluster_name_raises(self):
        from src.common.config import ActivityExportConfig

        with pytest.raises(ConfigurationError, match="Cluster name"):
            ActivityExportConfig(**self._valid_kwargs(cluster_name=""))

    def test_from_environment(self, monkeypatch):
        from src.common.config import ActivityExportConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        monkeypatch.setenv("VAULT_TOOLS_START_DATE", "2024-01-01")
        monkeypatch.setenv("VAULT_TOOLS_END_DATE", "2024-01-31")
        monkeypatch.setenv("VAULT_TOOLS_CLUSTER_NAME", "prod")

        cfg = ActivityExportConfig.from_environment()
        assert cfg.start_date == "2024-01-01"
        assert cfg.end_date == "2024-01-31"
        assert cfg.cluster_name == "prod"

    def test_from_environment_with_override(self, monkeypatch):
        from src.common.config import ActivityExportConfig

        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.test")
        monkeypatch.setenv("VAULT_TOOLS_START_DATE", "2024-01-01")
        monkeypatch.setenv("VAULT_TOOLS_END_DATE", "2024-01-31")
        monkeypatch.setenv("VAULT_TOOLS_CLUSTER_NAME", "prod")

        cfg = ActivityExportConfig.from_environment(cluster_name="override")
        assert cfg.cluster_name == "override"


class TestEntityExportConfig:
    def test_inherits_activity_export_config(self):
        from src.common.config import ActivityExportConfig, EntityExportConfig

        cfg = EntityExportConfig(
            vault_addr="https://vault.example.com",
            vault_token="s.test",
            start_date="2024-01-01",
            end_date="2024-01-31",
            cluster_name="cluster",
        )
        assert isinstance(cfg, ActivityExportConfig)


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
