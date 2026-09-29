"""Configuration loading.

Precedence (highest first): CLI flag > environment variable > config file > default.
The config file lives at ``$XDG_CONFIG_HOME/sherlog/config.toml``
(``~/.config/sherlog/config.toml`` by default).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sherlog.core.errors import ConfigError

ENV_CASES_DIR = "SHERLOG_CASES_DIR"
ENV_CONFIG_FILE = "SHERLOG_CONFIG"


def default_config_path() -> Path:
    """Location of the user config file, honouring ``SHERLOG_CONFIG`` and XDG."""
    if override := os.environ.get(ENV_CONFIG_FILE):
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "sherlog" / "config.toml"


def default_cases_dir() -> Path:
    """Default case storage: ``$XDG_DATA_HOME/sherlog/cases``."""
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "sherlog" / "cases"


def load_config_file(path: Path | None = None) -> dict[str, Any]:
    """Read the TOML config file; a missing file yields an empty mapping."""
    path = path or default_config_path()
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid config file {path}: {exc}") from exc


def default_cache_dir() -> Path:
    """Shared cache directory: ``$XDG_CACHE_HOME/sherlog``."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "sherlog"


@dataclass(frozen=True)
class Key:
    """A known configuration key: its type, env overrides, default and whether it is secret."""

    name: str
    type: type
    env: tuple[str, ...] = ()
    default: Any = None
    secret: bool = False
    help: str = ""


KEYS: dict[str, Key] = {
    k.name: k
    for k in (
        Key("cases_dir", str, (ENV_CASES_DIR,), help="Where case directories are stored."),
        Key(
            "offline",
            bool,
            ("SHERLOG_OFFLINE",),
            False,
            help="Never contact external services (enrichment, AI).",
        ),
        Key(
            "enrichment.abuseipdb_key",
            str,
            ("SHERLOG_ABUSEIPDB_KEY", "ABUSEIPDB_API_KEY"),
            secret=True,
            help="AbuseIPDB API key.",
        ),
        Key(
            "enrichment.virustotal_key",
            str,
            ("SHERLOG_VIRUSTOTAL_KEY", "VT_API_KEY", "VIRUSTOTAL_API_KEY"),
            secret=True,
            help="VirusTotal v3 API key.",
        ),
        Key("enrichment.cache_ttl_hours", float, (), 24.0, help="How long lookups are cached."),
        Key(
            "enrichment.geoip_db",
            str,
            ("SHERLOG_GEOIP_DB",),
            help="Path to a MaxMind .mmdb (GeoLite2-City/Country/ASN) for offline GeoIP.",
        ),
        Key(
            "enrichment.internal_domains",
            list,
            (),
            [],
            help="Domain suffixes that are never sent to external services.",
        ),
        Key("enrichment.virustotal_daily_limit", int, (), 500, help="Free tier: 500/day."),
        Key("enrichment.virustotal_min_interval", float, (), 15.0, help="Free tier: 4/min."),
        Key("enrichment.abuseipdb_daily_limit", int, (), 1000, help="Free tier: 1000/day."),
        Key("enrichment.abuseipdb_min_interval", float, (), 1.0, help="Seconds between calls."),
        Key(
            "ai.provider",
            str,
            ("SHERLOG_AI_PROVIDER",),
            help="anthropic, openai (any OpenAI-compatible API) or ollama; unset = AI off.",
        ),
        Key(
            "ai.model",
            str,
            ("SHERLOG_AI_MODEL",),
            help="Model name (default for anthropic: claude-sonnet-4-6; required otherwise).",
        ),
        Key(
            "ai.anthropic_key",
            str,
            ("ANTHROPIC_API_KEY",),
            secret=True,
            help="Anthropic API key (optional if an `ant auth login` profile is active).",
        ),
        Key("ai.openai_key", str, ("OPENAI_API_KEY",), secret=True, help="OpenAI-compatible key."),
        Key(
            "ai.openai_base_url",
            str,
            ("SHERLOG_OPENAI_BASE_URL",),
            "https://api.openai.com/v1",
            help="Base URL of the OpenAI-compatible API.",
        ),
        Key(
            "ai.ollama_url",
            str,
            ("OLLAMA_HOST",),
            "http://localhost:11434",
            help="Ollama server (local models).",
        ),
        Key("ai.max_iterations", int, (), 15, help="Maximum tool-use rounds per run."),
        Key("ai.token_budget", int, (), 200000, help="Input+output token cap per run."),
        Key(
            "ai.redact",
            bool,
            ("SHERLOG_AI_REDACT",),
            True,
            help="Pseudonymize hosts, internal IPs, usernames and emails sent to the model.",
        ),
        Key("ai.thinking", bool, (), True, help="Adaptive thinking on Anthropic models."),
    )
}


def _coerce(key: Key, value: Any) -> Any:
    """Convert a config/env/CLI value to the key's type."""
    if key.type is bool:
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off", ""):
            return False
        raise ConfigError(f"{key.name}: expected true/false, got {value!r}")
    if key.type is list:
        if isinstance(value, list):
            return [str(v) for v in value]
        return [v.strip() for v in str(value).split(",") if v.strip()]
    try:
        return key.type(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{key.name}: expected {key.type.__name__}, got {value!r}") from exc


def _lookup(data: dict[str, Any], dotted: str) -> Any:
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def get_setting(name: str, cli_value: Any = None, *, config: dict[str, Any] | None = None) -> Any:
    """Resolve one key: CLI value > environment > config file > default."""
    key = KEYS.get(name)
    if key is None:
        raise ConfigError(f"Unknown setting {name!r}")
    if cli_value is not None:
        return _coerce(key, cli_value)
    for env in key.env:
        if (value := os.environ.get(env)) not in (None, ""):
            return _coerce(key, value)
    file_value = _lookup(config if config is not None else load_config_file(), name)
    if file_value is not None:
        return _coerce(key, file_value)
    return key.default


def setting_source(name: str) -> str:
    """Where a setting's effective value comes from: env:<VAR>, file or default."""
    key = KEYS[name]
    for env in key.env:
        if os.environ.get(env) not in (None, ""):
            return f"env:{env}"
    return "file" if _lookup(load_config_file(), name) is not None else "default"


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    text = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{text}"'


def dump_toml(data: dict[str, Any]) -> str:
    """Serialize a config mapping (top-level values plus one level of tables)."""
    lines = [f"{k} = {_toml_value(v)}" for k, v in sorted(data.items()) if not isinstance(v, dict)]
    for table, values in sorted((k, v) for k, v in data.items() if isinstance(v, dict)):
        if values:
            lines.append(f"\n[{table}]")
            lines.extend(f"{k} = {_toml_value(v)}" for k, v in sorted(values.items()))
    return "\n".join(lines).lstrip("\n") + "\n"


def _write_config(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".toml.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # may hold API keys
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(dump_toml(data))
    os.replace(tmp, path)
    path.chmod(0o600)


def set_setting(name: str, value: Any, path: Path | None = None) -> Any:
    """Validate and persist a setting in the config file; returns the stored value."""
    key = KEYS.get(name)
    if key is None:
        raise ConfigError(f"Unknown setting {name!r}; known: {', '.join(sorted(KEYS))}")
    path = path or default_config_path()
    data = load_config_file(path)
    coerced = _coerce(key, value)
    node = data
    *parents, leaf = name.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = coerced
    _write_config(data, path)
    return coerced


def unset_setting(name: str, path: Path | None = None) -> bool:
    """Remove a setting from the config file; returns whether it was present."""
    if name not in KEYS:
        raise ConfigError(f"Unknown setting {name!r}")
    path = path or default_config_path()
    data = load_config_file(path)
    *parents, leaf = name.split(".")
    node = data
    for part in parents:
        node = node.get(part) or {}
    if leaf not in node:
        return False
    del node[leaf]
    _write_config(data, path)
    return True


def mask(value: Any) -> str:
    """Show only the last four characters of a secret."""
    text = str(value)
    return "*" * max(0, len(text) - 4) + text[-4:] if len(text) > 4 else "****"


@dataclass(frozen=True)
class Settings:
    """Resolved runtime settings."""

    cases_dir: Path


def resolve_settings(cases_dir: Path | None = None) -> Settings:
    """Resolve settings using CLI value > env var > config file > default."""
    if cases_dir is None and (env := os.environ.get(ENV_CASES_DIR)):
        cases_dir = Path(env)
    if cases_dir is None and (cfg := load_config_file().get("cases_dir")):
        cases_dir = Path(str(cfg))
    return Settings(cases_dir=(cases_dir or default_cases_dir()).expanduser().resolve())
