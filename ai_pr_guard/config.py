from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Optional

from dotenv import load_dotenv
from platformdirs import user_config_dir, user_data_dir


APP_NAME = "ai-pr-guard"


def _config_path() -> str:
    cfg_dir = user_config_dir(APP_NAME)
    os.makedirs(cfg_dir, exist_ok=True)
    return os.path.join(cfg_dir, "config.json")


def _data_path() -> str:
    data_dir = user_data_dir(APP_NAME)
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


@dataclass(frozen=True)
class Config:
    github_token: Optional[str]
    repo_full_name: Optional[str]  # "owner/repo"
    base_branch: Optional[str]

    llm_provider: str
    openai_api_key: Optional[str]
    openai_base_url: Optional[str]
    openai_model: str

    github_webhook_secret: Optional[str]
    max_diff_chars: int

    # Local storage
    data_dir: str
    db_path: str


def load_config() -> Config:
    # Load .env in current working directory if present
    load_dotenv(override=False)

    file_cfg = _read_file_config()
    data_dir = _data_path()
    db_path = os.path.join(data_dir, "ai_pr_guard.sqlite3")

    def pick(key: str, env_key: Optional[str] = None) -> Optional[str]:
        env_key = env_key or key
        # Check for Ollama specific env vars
        if key == "openai_base_url" and os.environ.get("OLLAMA_BASE_URL"):
            return os.environ.get("OLLAMA_BASE_URL")
        if key == "openai_model" and os.environ.get("OLLAMA_MODEL"):
            return os.environ.get("OLLAMA_MODEL")
        if key == "openai_api_key" and os.environ.get("OLLAMA_API_KEY"):
            return os.environ.get("OLLAMA_API_KEY")
        return os.environ.get(env_key) or file_cfg.get(key)

    max_diff = os.environ.get("MAX_DIFF_CHARS") or file_cfg.get("max_diff_chars") or "120000"
    try:
        max_diff_i = int(max_diff)
    except Exception:
        max_diff_i = 120000

    return Config(
        github_token=pick("github_token", "GITHUB_TOKEN"),
        repo_full_name=pick("repo_full_name", "REPO_FULL_NAME"),
        base_branch=pick("base_branch", "BASE_BRANCH"),
        llm_provider=(os.environ.get("LLM_PROVIDER") or file_cfg.get("llm_provider") or "openai").strip(),
        openai_api_key=pick("openai_api_key", "OPENAI_API_KEY"),
        openai_base_url=pick("openai_base_url", "OPENAI_BASE_URL"),
        openai_model=pick("openai_model", "OPENAI_MODEL") or "gpt-4.1-mini",
        github_webhook_secret=pick("github_webhook_secret", "GITHUB_WEBHOOK_SECRET"),
        max_diff_chars=max_diff_i,
        data_dir=data_dir,
        db_path=db_path,
    )


def save_config_updates(**updates: Any) -> None:
    cfg = _read_file_config()
    cfg.update({k: v for k, v in updates.items() if v is not None})
    path = _config_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, sort_keys=True)


def _read_file_config() -> dict[str, Any]:
    path = _config_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}
