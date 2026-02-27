from __future__ import annotations

import time
import sys
from typing import Optional

import typer

from .config import load_config, save_config_updates
from .github_api import GitHubClient, GitHubError
from .llm import LLMClient, LLMError
from .review import extract_checked_style_rules, run_review
from .storage import apply_style_feedback, get_review, init_db


app = typer.Typer(no_args_is_help=True, add_completion=False)


def _require_token(cfg_token: Optional[str]) -> str:
    token = cfg_token or ""
    if not token.strip():
        raise typer.BadParameter("GitHub token missing. Run `python -m ai_pr_guard connect` or set GITHUB_TOKEN.")
    return token.strip()


def _require_repo(repo_full_name: Optional[str]) -> str:
    if not repo_full_name:
        raise typer.BadParameter("Repository not selected. Run `python -m ai_pr_guard select-repo`.")
    return repo_full_name


def _require_branch(base_branch: Optional[str]) -> str:
    if not base_branch:
        raise typer.BadParameter("Base branch not selected. Run `python -m ai_pr_guard select-branch`.")
    return base_branch


@app.command("connect")
def connect() -> None:
    """
    Prompt for a GitHub token and save it locally.
    """
    cfg = load_config()
    token = typer.prompt("Paste your GitHub token (it will be stored locally)", hide_input=True)
    token = token.strip()
    if not token:
        raise typer.BadParameter("Empty token.")

    gh = GitHubClient(token)
    try:
        me = gh.get_user()
    except GitHubError as e:
        raise typer.BadParameter(f"Token validation failed: {e}") from e
    finally:
        gh.close()

    save_config_updates(github_token=token)
    typer.echo(f"Connected as: {me.get('login')}")


@app.command("select-repo")
def select_repo() -> None:
    """
    List accessible repos and store the selected repository.
    """
    cfg = load_config()
    token = _require_token(cfg.github_token)
    gh = GitHubClient(token)
    try:
        repos = gh.list_repos()
    finally:
        gh.close()

    if not repos:
        typer.echo("No repositories found for this token/user.")
        raise typer.Exit(code=1)

    # show top 50 most recently updated
    shown = repos[:50]
    for idx, r in enumerate(shown, start=1):
        full = r.get("full_name")
        priv = "private" if r.get("private") else "public"
        typer.echo(f"{idx:2d}. {full} ({priv})")

    choice = typer.prompt("Select repository number", type=int)
    if choice < 1 or choice > len(shown):
        raise typer.BadParameter("Invalid selection.")

    selected = shown[choice - 1].get("full_name")
    if not selected:
        raise typer.BadParameter("Selected repo missing full_name.")

    save_config_updates(repo_full_name=selected)
    typer.echo(f"Selected repo: {selected}")


@app.command("select-branch")
def select_branch() -> None:
    """
    List branches for the selected repo and store the selected base branch.
    """
    cfg = load_config()
    token = _require_token(cfg.github_token)
    repo = _require_repo(cfg.repo_full_name)

    gh = GitHubClient(token)
    try:
        branches = gh.list_branches(repo)
    finally:
        gh.close()

    if not branches:
        typer.echo("No branches found.")
        raise typer.Exit(code=1)

    shown = branches[:50]
    for idx, b in enumerate(shown, start=1):
        typer.echo(f"{idx:2d}. {b.get('name')}")

    choice = typer.prompt("Select base branch number", type=int)
    if choice < 1 or choice > len(shown):
        raise typer.BadParameter("Invalid selection.")
    selected = shown[choice - 1].get("name")
    if not selected:
        raise typer.BadParameter("Selected branch missing name.")

    save_config_updates(base_branch=selected)
    typer.echo(f"Selected base branch: {selected}")


@app.command("review-pr")
def review_pr(
    pr_number: int = typer.Argument(..., help="Pull request number"),
    repo: Optional[str] = typer.Option(None, "--repo", help='Override repo "owner/repo"'),
    base_branch: Optional[str] = typer.Option(None, "--base-branch", help="Override base branch"),
    no_comment: bool = typer.Option(False, "--no-comment", help="Do not post PR comment (dry run)"),
) -> None:
    """
    Review a PR and (by default) post a comment with findings.
    """
    cfg = load_config()
    token = _require_token(cfg.github_token)
    repo_full_name = repo or _require_repo(cfg.repo_full_name)
    base = base_branch or _require_branch(cfg.base_branch)

    init_db(cfg.db_path)

    gh = GitHubClient(token)
    try:
        llm = LLMClient(cfg.llm_provider, cfg.openai_api_key, cfg.openai_base_url, cfg.openai_model)
        result = run_review(
            gh=gh,
            llm=llm,
            db_path=cfg.db_path,
            repo_full_name=repo_full_name,
            pr_number=pr_number,
            base_branch=base,
            max_diff_chars=cfg.max_diff_chars,
            post_comment=(not no_comment),
        )
    except (GitHubError, LLMError) as e:
        typer.echo(str(e))
        raise typer.Exit(code=1)
    finally:
        gh.close()

    typer.echo(f"Reviewed PR #{pr_number} in {repo_full_name}")
    typer.echo(f"- Findings: {result['findings_total']} (static {result['static_findings']}, llm {result['llm_findings']})")
    if result.get("comment_id"):
        typer.echo(f"- Comment ID: {result['comment_id']}")


@app.command("sync-feedback")
def sync_feedback(
    pr_number: int = typer.Argument(..., help="Pull request number"),
    repo: Optional[str] = typer.Option(None, "--repo", help='Override repo "owner/repo"'),
) -> None:
    """
    Fetch the latest Sentinel comment on a PR and learn from checked items.
    """
    cfg = load_config()
    token = _require_token(cfg.github_token)
    repo_full_name = repo or _require_repo(cfg.repo_full_name)
    init_db(cfg.db_path)

    gh = GitHubClient(token)
    try:
        comments = gh.list_issue_comments(repo_full_name, pr_number)
    finally:
        gh.close()

    marker = "<!-- ai-pr-guard:review -->"
    target = None
    for c in reversed(comments):
        body = c.get("body") or ""
        if marker in body:
            target = c
            break

    if not target:
        typer.echo("No Sentinel review comment found on this PR.")
        raise typer.Exit(code=1)

    body = target.get("body") or ""
    accepted_rules = extract_checked_style_rules(body)
    if not accepted_rules:
        typer.echo("No checked items detected yet. Check some findings in GitHub and re-run.")
        raise typer.Exit(code=0)

    apply_style_feedback(cfg.db_path, accepted_rules=accepted_rules)
    typer.echo(f"Learned {len(accepted_rules)} style rule(s):")
    for r in accepted_rules:
        typer.echo(f"- {r}")


@app.command("run-webhook")
def run_webhook(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port"),
) -> None:
    """
    Run FastAPI server (dashboard + webhook).
    """
    try:
        import uvicorn
    except Exception as e:
        typer.echo(f"uvicorn import failed: {e}")
        raise typer.Exit(code=1)

    from .webhook import create_app

    uvicorn.run(create_app(), host=host, port=port)


@app.command("run-dashboard")
def run_dashboard(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port"),
) -> None:
    """
    Run the web UI dashboard (same server also exposes /github/webhook).
    """
    try:
        import uvicorn
    except Exception as e:
        typer.echo(f"uvicorn import failed: {e}")
        raise typer.Exit(code=1)

    from .webhook import create_app

    uvicorn.run(create_app(), host=host, port=port)


@app.command("run-poller")
def run_poller(
    interval_seconds: int = typer.Option(300, "--interval-seconds", help="Polling interval"),
    once: bool = typer.Option(False, "--once", help="Run one poll cycle then exit"),
) -> None:
    """
    Continuously poll for open PRs on the selected repo/base branch and review when new commits arrive.
    """
    cfg = load_config()
    token = _require_token(cfg.github_token)
    repo_full_name = _require_repo(cfg.repo_full_name)
    base = _require_branch(cfg.base_branch)
    init_db(cfg.db_path)

    typer.echo(f"Configuration: repo={repo_full_name}, base_branch={base}")
    
    gh = GitHubClient(token)
    try:
        # Debug: List ALL open PRs without base filter to see what's available
        all_pulls = gh.list_open_pulls(repo_full_name)
        typer.echo(f"Debug: Total open PRs in repo: {len(all_pulls)}")
        
        # Show PR numbers and their base branches
        for pr in all_pulls[:10]:
            pr_num = pr.get("number")
            pr_base = (pr.get("base") or {}).get("ref")
            pr_head = (pr.get("head") or {}).get("ref")
            typer.echo(f"  PR #{pr_num}: base={pr_base}, head={pr_head}")
        
        llm = LLMClient(cfg.llm_provider, cfg.openai_api_key, cfg.openai_base_url, cfg.openai_model)
        while True:
            pulls = gh.list_open_pulls(repo_full_name, base_branch=base)
            reviewed = 0
            skipped = 0
            for pr in pulls:
                num = int(pr.get("number"))
                head_sha = (pr.get("head") or {}).get("sha")
                prev = get_review(cfg.db_path, repo_full_name, num)
                prev_sha = (prev.findings or {}).get("head_sha") if prev else None
                if head_sha and prev_sha == head_sha:
                    skipped += 1
                    continue
                run_review(
                    gh=gh,
                    llm=llm,
                    db_path=cfg.db_path,
                    repo_full_name=repo_full_name,
                    pr_number=num,
                    base_branch=base,
                    max_diff_chars=cfg.max_diff_chars,
                    post_comment=True,
                )
                reviewed += 1

            typer.echo(f"Poll cycle done: reviewed {reviewed}, skipped {skipped}, open PRs matching base branch '{base}': {len(pulls)}")
            if once:
                break
            time.sleep(max(10, int(interval_seconds)))
    except (GitHubError, LLMError) as e:
        typer.echo(str(e))
        raise typer.Exit(code=1)
    finally:
        gh.close()


def main(argv: Optional[list[str]] = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    app(prog_name="ai_pr_guard", args=argv)

