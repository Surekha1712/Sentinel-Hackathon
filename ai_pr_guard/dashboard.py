from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .config import load_config, save_config_updates
from .github_api import GitHubClient, GitHubError
from .llm import LLMClient, LLMError
from .review import run_review
from .storage import get_metrics_summary, get_review, init_db, list_recent_reviews, list_style_rules


def attach_dashboard(app: FastAPI) -> None:
    cfg = load_config()
    init_db(cfg.db_path)

    templates_dir = Path(__file__).resolve().parent / "templates"
    templates = Jinja2Templates(directory=str(templates_dir))

    def _flash(title: str, message: str) -> dict[str, str]:
        return {"title": title, "message": message}

    @app.get("/", response_class=HTMLResponse)
    async def root() -> RedirectResponse:
        return RedirectResponse(url="/dashboard", status_code=302)

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard(request: Request) -> HTMLResponse:
        cfg2 = load_config()
        ready = bool(cfg2.github_token and cfg2.repo_full_name and cfg2.base_branch)
        connected = bool(cfg2.github_token)
        
        # Get metrics for dashboard
        metrics = {}
        recent_reviews = []
        if connected and cfg2.repo_full_name:
            metrics = get_metrics_summary(cfg2.db_path, days=30)
            # Get recent reviews for activity feed
            recent_rows = list_recent_reviews(cfg2.db_path, cfg2.repo_full_name, limit=5)
            for r in recent_rows:
                meta = r.findings or {}
                recent_reviews.append({
                    "pr_number": r.pr_number,
                    "created_at_human": _human_ts(r.created_at),
                    "findings_total": len(meta.get("findings", [])),
                })
        
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "title": "Dashboard",
                "connected": connected,
                "repo_full_name": cfg2.repo_full_name,
                "base_branch": cfg2.base_branch,
                "llm_provider": cfg2.llm_provider,
                "llm_model": cfg2.openai_model,
                "ready": ready,
                "metrics": metrics,
                "recent_reviews": recent_reviews,
            },
        )

    @app.get("/connect", response_class=HTMLResponse)
    async def connect_get(request: Request) -> HTMLResponse:
        cfg2 = load_config()
        me = None
        if cfg2.github_token:
            try:
                gh = GitHubClient(cfg2.github_token)
                me = gh.get_user()
                gh.close()
            except Exception:
                me = None
        return templates.TemplateResponse("connect.html", {"request": request, "title": "Connect", "me": me})

    @app.post("/connect")
    async def connect_post(token: str = Form(...)) -> RedirectResponse:
        token = (token or "").strip()
        if not token:
            raise HTTPException(status_code=400, detail="Empty token")
        gh = GitHubClient(token)
        try:
            gh.get_user()
        except GitHubError as e:
            raise HTTPException(status_code=400, detail=f"Token validation failed: {e}") from e
        finally:
            gh.close()

        save_config_updates(github_token=token)
        return RedirectResponse(url="/dashboard", status_code=303)

    @app.get("/select-repo", response_class=HTMLResponse)
    async def select_repo_get(request: Request) -> HTMLResponse:
        cfg2 = load_config()
        if not cfg2.github_token:
            return templates.TemplateResponse(
                "base.html",
                {"request": request, "title": "Select repo", "flash": _flash("Not connected", "Connect to GitHub first.")},
                status_code=400,
            )

        gh = GitHubClient(cfg2.github_token)
        try:
            repos = gh.list_repos()[:50]
        finally:
            gh.close()

        repos_slim = [{"full_name": r.get("full_name"), "private": bool(r.get("private"))} for r in repos if r.get("full_name")]
        return templates.TemplateResponse(
            "select_repo.html",
            {"request": request, "title": "Select repo", "repos": repos_slim, "selected": cfg2.repo_full_name},
        )

    @app.post("/select-repo")
    async def select_repo_post(repo_full_name: str = Form(...)) -> RedirectResponse:
        repo_full_name = (repo_full_name or "").strip()
        if "/" not in repo_full_name:
            raise HTTPException(status_code=400, detail="Invalid repo_full_name")
        save_config_updates(repo_full_name=repo_full_name)
        return RedirectResponse(url="/dashboard", status_code=303)

    @app.get("/select-branch", response_class=HTMLResponse)
    async def select_branch_get(request: Request) -> HTMLResponse:
        cfg2 = load_config()
        if not (cfg2.github_token and cfg2.repo_full_name):
            return templates.TemplateResponse(
                "base.html",
                {
                    "request": request,
                    "title": "Select branch",
                    "flash": _flash("Missing config", "Connect and select a repo first."),
                },
                status_code=400,
            )

        gh = GitHubClient(cfg2.github_token)
        try:
            branches = gh.list_branches(cfg2.repo_full_name)[:50]
        finally:
            gh.close()

        branches_slim = [{"name": b.get("name")} for b in branches if b.get("name")]
        return templates.TemplateResponse(
            "select_branch.html",
            {
                "request": request,
                "title": "Select branch",
                "branches": branches_slim,
                "selected": cfg2.base_branch,
                "repo_full_name": cfg2.repo_full_name,
            },
        )

    @app.post("/select-branch")
    async def select_branch_post(base_branch: str = Form(...)) -> RedirectResponse:
        base_branch = (base_branch or "").strip()
        if not base_branch:
            raise HTTPException(status_code=400, detail="Empty base_branch")
        save_config_updates(base_branch=base_branch)
        return RedirectResponse(url="/dashboard", status_code=303)

    @app.post("/review")
    async def trigger_review(background: BackgroundTasks, pr_number: int = Form(...)) -> RedirectResponse:
        cfg2 = load_config()
        if not (cfg2.github_token and cfg2.repo_full_name and cfg2.base_branch):
            raise HTTPException(status_code=400, detail="Connect, select repo, and select base branch first.")
        if pr_number <= 0:
            raise HTTPException(status_code=400, detail="Invalid PR number")

        background.add_task(_do_review, int(pr_number))
        return RedirectResponse(url=f"/reviews/{int(pr_number)}", status_code=303)

    @app.get("/reviews", response_class=HTMLResponse)
    async def reviews(request: Request) -> HTMLResponse:
        cfg2 = load_config()
        if not cfg2.repo_full_name:
            return templates.TemplateResponse("reviews.html", {"request": request, "title": "Reviews", "repo_full_name": None, "reviews": []})
        rows = list_recent_reviews(cfg2.db_path, cfg2.repo_full_name, limit=50)
        view = []
        for r in rows:
            meta = r.findings or {}
            findings_total = len(meta.get("findings") or [])
            llm_parse_ok = bool(meta.get("llm_parse_ok"))
            created_h = _human_ts(r.created_at)
            
            # Get scores if available
            scores = meta.get("scores", {})
            
            view.append(
                {
                    "pr_number": r.pr_number,
                    "created_at_human": created_h,
                    "findings_total": findings_total,
                    "llm_parse_ok": llm_parse_ok,
                    "risk_level": scores.get("risk_level", "N/A") if scores else "N/A",
                    "security_score": scores.get("security_score", 0) if scores else 0,
                }
            )
        return templates.TemplateResponse(
            "reviews.html",
            {"request": request, "title": "Reviews", "repo_full_name": cfg2.repo_full_name, "reviews": view},
        )

    @app.get("/reviews/{pr_number}", response_class=HTMLResponse)
    async def review_detail(request: Request, pr_number: int) -> HTMLResponse:
        cfg2 = load_config()
        if not cfg2.repo_full_name:
            raise HTTPException(status_code=400, detail="Select a repo first.")
        record = get_review(cfg2.db_path, cfg2.repo_full_name, int(pr_number))
        meta = (record.findings if record else {}) or {}
        findings = meta.get("findings") or []
        scores = meta.get("scores", {})
        
        return templates.TemplateResponse(
            "review_detail.html",
            {
                "request": request,
                "title": f"PR #{pr_number}",
                "repo_full_name": cfg2.repo_full_name,
                "pr_number": int(pr_number),
                "record": record,
                "findings_total": len(findings),
                "static_count": int(meta.get("static_count") or 0),
                "llm_parse_ok": bool(meta.get("llm_parse_ok")),
                "head_sha": meta.get("head_sha"),
                "findings": findings,
                "llm_raw": meta.get("llm_raw"),
                "scores": scores,
            },
        )


def _do_review(pr_number: int) -> None:
    cfg = load_config()
    if not (cfg.github_token and cfg.repo_full_name and cfg.base_branch):
        return
    init_db(cfg.db_path)

    gh = GitHubClient(cfg.github_token)
    try:
        llm = LLMClient(cfg.llm_provider, cfg.openai_api_key, cfg.openai_base_url, cfg.openai_model)
        run_review(
            gh=gh,
            llm=llm,
            db_path=cfg.db_path,
            repo_full_name=cfg.repo_full_name,
            pr_number=int(pr_number),
            base_branch=cfg.base_branch,
            max_diff_chars=cfg.max_diff_chars,
            post_comment=True,
        )
    except (GitHubError, LLMError):
        return
    finally:
        gh.close()


def _human_ts(ts: int) -> str:
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(ts)
