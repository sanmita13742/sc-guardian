"""Layered, validated configuration.

Precedence (highest first):  environment variable ``SCANNER_<NAME>``  >  ``.env`` (loaded into the environment)  >  ``scanner.toml``  >  built-in default.

* The config file is ``scanner.toml`` in the project root, or the path in ``SCANNER_CONFIG``. See ``scanner.example.toml``.
* Every value is type- and range-checked. An invalid value never crashes the app: it is ignored, the default is used, and the problem is
  listed (Settings & Health page, ``Settings.problems``).
* Secrets (API keys) are accepted from the environment only; a secret found in the file is rejected and reported.
* ``Settings.sources`` records where each effective value came from.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

# name -> (type, minimum, maximum, meaning)
TUNABLES: dict[str, tuple[type, float, float, str]] = {
    "clone_timeout_s": (int, 10, 3600, "git clone time limit (seconds)"),
    "clone_depth": (int, 1, 5000, "shallow clone depth (commits)"),
    "max_repo_bytes": (int, 1_000_000, 20_000_000_000, "largest repository accepted (bytes)"),
    "max_files_walked": (int, 1000, 5_000_000, "file walk cap during inspection"),
    "syft_timeout_s": (int, 10, 7200, "Syft/Trivy run time limit (seconds)"),
    "max_file_bytes": (int, 10_000, 500_000_000, "largest manifest/lockfile parsed (bytes)"),
    "http_timeout_s": (int, 3, 300, "HTTP timeout for OSV/NVD/KEV/registries (seconds)"),
    "http_retries": (int, 0, 10, "HTTP retries"),
    "osv_batch_size": (int, 1, 1000, "OSV batch size"),
    "osv_workers": (int, 1, 32, "parallel OSV requests"),
    "nvd_max_cves_no_key": (int, 0, 1000, "NVD CVE lookups without an API key"),
    "nvd_max_cves_with_key": (int, 0, 5000, "NVD CVE lookups with an API key"),
    "metadata_budget_s": (int, 5, 1800, "registry metadata look-up budget per scan (seconds)"),
    "scan_cache_ttl_s": (int, 0, 31_536_000, "reuse a stored scan of the same commit for at most this long (seconds)"),
    "workspace_max_age_s": (int, 60, 604_800, "orphaned clone workspaces older than this are deleted (seconds)"),
    "keep_scans_per_repo": (int, 1, 1000, "scans kept per repository"),
    "investigator_llm_max": (int, 0, 100, "findings the optional LLM may investigate per scan"),
    "investigator_max_steps": (int, 1, 12, "tool calls per LLM investigation"),
    "remediation_max_groups": (int, 0, 100, "source-package groups planned per scan"),
    "remediation_budget_s": (int, 10, 1800, "time budget for remediation planning (seconds)"),
    "cache_max_rows": (int, 1000, 50_000_000, "upper bound for rows in the TTL cache"),
    "cache_max_age_days": (int, 1, 3650, "cache rows older than this are purged"),
    "max_paths_per_target": (int, 1, 500, "dependency paths kept per finding"),
    "max_path_depth": (int, 2, 200, "deepest dependency path enumerated"),
}
STRINGS = {"syft_bin": "Syft executable", "trivy_bin": "Trivy executable", "llm_model": "optional LLM model name (default per provider)", "llm_provider": "optional LLM provider (auto-detected from LLM_API_KEY)", "llm_base_url": "base URL for an OpenAI-compatible LLM endpoint"}
PATHS = {"data_dir": "SQLite database folder", "workspace_dir": "temporary clone folder"}
SECRETS = {"nvd_api_key", "llm_api_key", "anthropic_api_key"}
ROOT = Path(__file__).resolve().parent.parent


def _coerce(name: str, raw: Any) -> tuple[Any, str | None]:
    typ, lo, hi, _ = TUNABLES[name]
    try:
        if isinstance(raw, bool):
            raise ValueError("boolean is not a number")
        v = typ(raw)
    except (TypeError, ValueError):
        return None, f"{name}: '{raw}' is not a valid {typ.__name__}"
    if not (lo <= v <= hi):
        return None, f"{name}: {v} is outside the allowed range {int(lo)}..{int(hi)}"
    return v, None


def config_file() -> Path:
    return Path(os.environ.get("SCANNER_CONFIG") or ROOT / "scanner.toml").expanduser()


def apply(settings: Any) -> Any:
    """Apply scanner.toml and SCANNER_* environment overrides to ``settings`` in place; returns it."""
    sources: dict[str, str] = {}
    problems: list[str] = []
    file_vals: dict[str, Any] = {}
    cf = config_file()
    file_found = cf.exists()
    if file_found:
        try:
            file_vals = tomllib.loads(cf.read_text(encoding="utf-8"))
        except Exception as e:
            problems.append(f"{cf.name}: cannot be parsed ({type(e).__name__}: {e}); file ignored")
            file_vals = {}
    for k in file_vals:
        if k.lower() in SECRETS:
            problems.append(f"{cf.name}: '{k}' is a secret and must be set via environment variable, not in the file (ignored)")
        elif k not in TUNABLES and k not in STRINGS and k not in PATHS:
            problems.append(f"{cf.name}: unknown key '{k}' (ignored)")

    def pick(name: str):
        env = os.environ.get(f"SCANNER_{name.upper()}")
        if env not in (None, ""):
            return env, "env"
        if name in file_vals and name.lower() not in SECRETS:
            return file_vals[name], "file"
        return None, "default"

    for name in TUNABLES:
        raw, src = pick(name)
        if src != "default":
            v, err = _coerce(name, raw)
            if err:
                problems.append(f"{err} ({src}); using default {getattr(settings, name)}")
            else:
                setattr(settings, name, v)
                sources[name] = src
                continue
        sources[name] = "default"
    for name in STRINGS:
        raw, src = pick(name)
        legacy = {"syft_bin": "SYFT_BIN", "trivy_bin": "TRIVY_BIN", "llm_model": "LLM_MODEL", "llm_provider": "LLM_PROVIDER", "llm_base_url": "LLM_BASE_URL"}[name]
        if src == "default" and os.environ.get(legacy):
            raw, src = os.environ[legacy], "env"
        if src != "default" and isinstance(raw, str) and raw.strip():
            setattr(settings, name, raw.strip())
            sources[name] = src
        else:
            sources[name] = "default"
    for name in PATHS:
        raw, src = pick(name)
        legacy = {"data_dir": "SCANNER_DATA_DIR", "workspace_dir": "SCANNER_WORKSPACE_DIR"}[name]
        if src == "default" and os.environ.get(legacy):
            raw, src = os.environ[legacy], "env"
        if src != "default" and isinstance(raw, str) and raw.strip():
            setattr(settings, name, Path(raw).expanduser().resolve())
            sources[name] = src
        else:
            sources[name] = "default"
    for sec, envs in (("nvd_api_key", ("NVD_API_KEY",)), ("llm_api_key", ("LLM_API_KEY", "ANTHROPIC_API_KEY"))):
        sources[sec] = "env" if any(os.environ.get(e) for e in envs) else "unset"
    if settings.nvd_max_cves_with_key < settings.nvd_max_cves_no_key:
        problems.append("nvd_max_cves_with_key is lower than nvd_max_cves_no_key")
    settings.sources, settings.problems, settings.config_file = sources, problems, (str(cf) if file_found else None)
    return settings


def effective(settings: Any) -> list[dict]:
    """Rows for display: name, value (secrets masked), source, meaning."""
    rows = []
    for name, (_, lo, hi, doc) in TUNABLES.items():
        rows.append({"setting": name, "value": getattr(settings, name), "source": settings.sources.get(name, "default"), "allowed": f"{int(lo)}..{int(hi)}", "meaning": doc})
    for name, doc in {**STRINGS, **PATHS}.items():
        rows.append({"setting": name, "value": str(getattr(settings, name)), "source": settings.sources.get(name, "default"), "allowed": "text", "meaning": doc})
    for name, label in (("nvd_api_key", "NVD API key (env NVD_API_KEY)"), ("llm_api_key", "optional LLM API key (env LLM_API_KEY: Groq, Gemini, Anthropic or OpenAI-compatible)")):
        rows.append({"setting": name, "value": "set (hidden)" if getattr(settings, name) else "not set", "source": settings.sources.get(name, "unset"), "allowed": "environment only", "meaning": label})
    return rows
