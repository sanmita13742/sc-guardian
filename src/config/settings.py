"""Runtime configuration (layered: env > .env > scanner.toml > defaults; see config/loader.py). Secrets come from environment variables only."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

try:  # optional
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass

ROOT = Path(__file__).resolve().parent.parent.parent  # repository root (src/config/ -> repo)


def _env_path(name: str, default: Path) -> Path:
    v = os.environ.get(name)
    return Path(v).expanduser().resolve() if v else default


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: _env_path("SCANNER_DATA_DIR", ROOT / "data"))
    workspace_dir: Path = field(default_factory=lambda: _env_path("SCANNER_WORKSPACE_DIR", ROOT / ".workspaces"))
    artifacts_dir: Path = field(default_factory=lambda: ROOT / "artifacts")
    syft_bin: str = field(default_factory=lambda: os.environ.get("SYFT_BIN") or shutil.which("syft") or "syft")
    trivy_bin: str = field(default_factory=lambda: os.environ.get("TRIVY_BIN") or shutil.which("trivy") or "trivy")
    nvd_api_key: str | None = field(default_factory=lambda: os.environ.get("NVD_API_KEY") or None)
    llm_api_key: str | None = field(default_factory=lambda: os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or None)
    llm_provider: str | None = field(default_factory=lambda: os.environ.get("LLM_PROVIDER") or None)  # groq | gemini | anthropic | openai | openai_compatible (auto-detected from the key)
    llm_model: str | None = field(default_factory=lambda: os.environ.get("LLM_MODEL") or os.environ.get("EXPLAIN_LLM_MODEL") or None)
    llm_base_url: str | None = field(default_factory=lambda: os.environ.get("LLM_BASE_URL") or None)

    # clone / scan limits
    clone_timeout_s: int = 180
    clone_depth: int = 50
    max_repo_bytes: int = 600 * 1024 * 1024
    max_files_walked: int = 200_000
    syft_timeout_s: int = 600
    max_file_bytes: int = 20 * 1024 * 1024  # per parsed manifest/lockfile

    # network
    http_timeout_s: int = 25
    http_retries: int = 3
    osv_batch_size: int = 500
    osv_workers: int = 8
    nvd_max_cves_no_key: int = 20
    nvd_max_cves_with_key: int = 300

    # metadata fusion
    metadata_budget_s: int = 120  # wall-clock budget for registry look-ups per scan (results are cached)

    # freshness / retention
    scan_cache_ttl_s: int = 24 * 3600  # a stored scan of the same commit is reused only while younger than this
    workspace_max_age_s: int = 3600  # orphaned clone workspaces older than this are removed at start
    keep_scans_per_repo: int = 20

    # investigator
    investigator_llm_max: int = 8  # findings the optional LLM may investigate per scan
    investigator_max_steps: int = 5  # tool calls per LLM investigation

    # remediation
    remediation_max_groups: int = 12  # source-package groups planned per scan (highest priority first)
    remediation_budget_s: int = 150  # wall-clock budget for planning

    # cache bounds
    cache_max_rows: int = 2_000_000
    cache_max_age_days: int = 120

    # graph
    max_paths_per_target: int = 25
    max_path_depth: int = 40

    # filled by config.loader.apply(): where each value came from and what was wrong with the configuration
    sources: dict = field(default_factory=dict, repr=False)
    problems: list = field(default_factory=list, repr=False)
    config_file: str | None = field(default=None, repr=False)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "scanner.db"


def get_settings() -> Settings:
    from config.loader import apply
    s = apply(Settings())
    s.data_dir.mkdir(parents=True, exist_ok=True)
    s.workspace_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("sbom", "scans", "reports", "graphs"):
        (s.artifacts_dir / sub).mkdir(parents=True, exist_ok=True)
    return s
