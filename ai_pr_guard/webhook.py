from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

from .config import load_config
from .dashboard import attach_dashboard
from .github_api import GitHubClient, GitHubError, verify_github_signature
from .llm import LLMClient, LLMError
from .review import run_review
from .sentinel import SentinelClient, create_security_alert
from .storage import init_db


def create_app() -> FastAPI:
    cfg = load_config()
    init_db(cfg.db_path)

    app = FastAPI(title="Sentinel", version="0.1.0")
    attach_dashboard(app)
    
    # Initialize Sentinel client for security alerts
    sentinel = SentinelClient()

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": True}

    @app.get("/sentinel-status")
    async def sentinel_status() -> dict[str, Any]:
        """Check Sentinel integration status."""
        return {
            "enabled": sentinel.enabled,
            "configured": sentinel.is_configured(),
            "workspace_id": bool(sentinel.workspace_id),
            "webhook_url": bool(sentinel.webhook_url),
        }

    @app.post("/github/webhook")
    async def github_webhook(
        request: Request,
        background: BackgroundTasks,
        x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
        x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
    ) -> dict[str, Any]:
        body = await request.body()

        if cfg.github_webhook_secret:
            if not verify_github_signature(body, x_hub_signature_256, cfg.github_webhook_secret):
                raise HTTPException(status_code=401, detail="Invalid webhook signature")

        if x_github_event != "pull_request":
            return {"ok": True, "ignored": True, "reason": "not pull_request event"}

        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")

        action = payload.get("action")
        if action not in {"opened", "reopened", "synchronize", "ready_for_review"}:
            return {"ok": True, "ignored": True, "reason": f"action {action} not handled"}

        repo_full_name = (payload.get("repository") or {}).get("full_name")
        pr_number = (payload.get("pull_request") or {}).get("number")
        pr_base_ref = ((payload.get("pull_request") or {}).get("base") or {}).get("ref")

        if not repo_full_name or not pr_number:
            raise HTTPException(status_code=400, detail="Missing repository.full_name or pull_request.number")

        # If user configured a specific repo/branch, only act on those
        if cfg.repo_full_name and repo_full_name != cfg.repo_full_name:
            return {"ok": True, "ignored": True, "reason": "repo not selected in local config"}
        if cfg.base_branch and pr_base_ref and pr_base_ref != cfg.base_branch:
            return {"ok": True, "ignored": True, "reason": "base branch does not match config"}

        if not cfg.github_token:
            raise HTTPException(status_code=500, detail="Server missing GITHUB_TOKEN / saved token")

        # fire-and-forget review with Sentinel integration
        background.add_task(_background_review, repo_full_name, int(pr_number))
        return {"ok": True, "queued": True, "repo": repo_full_name, "pr_number": int(pr_number)}

    return app


def _background_review(repo_full_name: str, pr_number: int) -> None:
    cfg = load_config()
    if not cfg.github_token:
        return
    if not cfg.base_branch:
        return

    gh = GitHubClient(cfg.github_token)
    sentinel = SentinelClient()
    
    try:
        llm = LLMClient(cfg.llm_provider, cfg.openai_api_key, cfg.openai_base_url, cfg.openai_model)
        result = run_review(
            gh=gh,
            llm=llm,
            db_path=cfg.db_path,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            base_branch=cfg.base_branch,
            max_diff_chars=cfg.max_diff_chars,
            post_comment=True,
        )
        
        # ====== FEATURE 5: Send Sentinel Alert ======
        if sentinel.is_configured() and result:
            scores = result.get("scores", {})
            findings = result.get("findings_total", 0)
            if scores:
                alert = create_security_alert(
                    pr_number=pr_number,
                    repo_full_name=repo_full_name,
                    findings=[],  # Findings already stored in DB
                    scores=scores,
                )
                if alert:
                    sentinel.send_security_alert(alert)
                    
    except (GitHubError, LLMError):
        # For MVP: swallow errors (could log to file/telemetry)
        return
    finally:
        gh.close()
