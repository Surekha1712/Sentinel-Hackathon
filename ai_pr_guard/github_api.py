from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Iterable, Optional

import httpx


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, token: str, base_url: str = "https://api.github.com") -> None:
        self._token = token
        self._base_url = base_url.rstrip("/")
        scheme = _guess_auth_scheme(self._token)
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"{scheme} {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "ai-pr-guard",
            },
            timeout=30.0,
        )

    def close(self) -> None:
        self._client.close()

    def get_user(self) -> dict[str, Any]:
        return self._get_json("/user")

    def list_repos(self, per_page: int = 100, max_items: int = 500) -> list[dict[str, Any]]:
        return list(self._paginate("/user/repos", params={"per_page": per_page, "sort": "updated"}, max_items=max_items))

    def list_branches(self, repo_full_name: str, per_page: int = 100, max_items: int = 500) -> list[dict[str, Any]]:
        return list(
            self._paginate(f"/repos/{repo_full_name}/branches", params={"per_page": per_page}, max_items=max_items)
        )

    def get_pull(self, repo_full_name: str, pr_number: int) -> dict[str, Any]:
        return self._get_json(f"/repos/{repo_full_name}/pulls/{pr_number}")

    def list_open_pulls(
        self,
        repo_full_name: str,
        base_branch: Optional[str] = None,
        per_page: int = 100,
        max_items: int = 500,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"state": "open", "per_page": per_page}
        if base_branch:
            params["base"] = base_branch
        return list(self._paginate(f"/repos/{repo_full_name}/pulls", params=params, max_items=max_items))

    def list_pull_files(self, repo_full_name: str, pr_number: int, per_page: int = 100, max_items: int = 1000) -> list[dict[str, Any]]:
        return list(
            self._paginate(
                f"/repos/{repo_full_name}/pulls/{pr_number}/files",
                params={"per_page": per_page},
                max_items=max_items,
            )
        )

    def list_issue_comments(self, repo_full_name: str, issue_number: int, per_page: int = 100, max_items: int = 1000) -> list[dict[str, Any]]:
        return list(
            self._paginate(
                f"/repos/{repo_full_name}/issues/{issue_number}/comments",
                params={"per_page": per_page},
                max_items=max_items,
            )
        )

    def create_issue_comment(self, repo_full_name: str, issue_number: int, body: str) -> dict[str, Any]:
        return self._post_json(f"/repos/{repo_full_name}/issues/{issue_number}/comments", json_body={"body": body})

    def _get_json(self, path: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        r = self._client.get(path, params=params)
        if r.status_code >= 400:
            raise GitHubError(f"GitHub API error {r.status_code}: {r.text}")
        return r.json()

    def _post_json(self, path: str, json_body: dict[str, Any]) -> dict[str, Any]:
        r = self._client.post(path, json=json_body)
        if r.status_code >= 400:
            raise GitHubError(f"GitHub API error {r.status_code}: {r.text}")
        return r.json()

    def _paginate(self, path: str, params: Optional[dict[str, Any]] = None, max_items: int = 1000) -> Iterable[dict[str, Any]]:
        url = path
        remaining = max_items
        while url and remaining > 0:
            r = self._client.get(url, params=params)
            if r.status_code >= 400:
                raise GitHubError(f"GitHub API error {r.status_code}: {r.text}")
            items = r.json()
            if not isinstance(items, list):
                raise GitHubError(f"Expected list response from {url}, got {type(items)}")
            for it in items:
                yield it
                remaining -= 1
                if remaining <= 0:
                    break
            url = self._next_link(r.headers.get("Link"))
            params = None  # next link already has query

    @staticmethod
    def _next_link(link_header: Optional[str]) -> Optional[str]:
        if not link_header:
            return None
        # Example: <https://api.github.com/user/repos?page=2>; rel="next", <...>; rel="last"
        parts = [p.strip() for p in link_header.split(",")]
        for p in parts:
            if 'rel="next"' in p:
                start = p.find("<")
                end = p.find(">")
                if start != -1 and end != -1 and end > start:
                    return p[start + 1 : end]
        return None


def verify_github_signature(body_bytes: bytes, signature_header: Optional[str], secret: str) -> bool:
    """
    Verify GitHub webhook signature (X-Hub-Signature-256: sha256=...).
    """
    if not secret:
        return False
    if not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    given = signature_header.split("=", 1)[1].strip()
    return hmac.compare_digest(expected, given)


def compact_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _guess_auth_scheme(token: str) -> str:
    """
    GitHub accepts both 'token' (classic PAT) and 'Bearer' (fine-grained/App tokens) in many cases.
    We pick a reasonable default based on common token prefixes.
    """
    t = (token or "").strip()
    if t.startswith("ghp_") or t.startswith("gho_") or t.startswith("ghu_") or t.startswith("ghs_") or t.startswith("ghr_"):
        return "token"
    if t.startswith("github_pat_"):
        return "Bearer"
    return "Bearer"
