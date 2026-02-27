from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass
from typing import Any, Optional

from .github_api import GitHubClient
from .llm import LLMClient, LLMError
from .scoring import calculate_all_scores, format_scores_markdown
from .storage import apply_style_feedback, get_style_notes, init_db, record_metric, upsert_review


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    details: str
    suggestion: str
    style_rule: str
    source: str  # "static" | "llm"


# Enhanced Security Patterns for Security-Focused Mode
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Original secret patterns
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{80,}\b")),
    ("Generic API key", re.compile(r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    # Additional secret patterns
    ("Azure access key", re.compile(r"\b[a-zA-Z0-9+/]{86}==\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Stripe API key", re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}\b")),
    ("Database URL with credentials", re.compile(r"(?i)(mysql|postgres|mongodb)://[^:]+:[^@]+@")),
    ("JWT token", re.compile(r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b")),
]

# SQL Injection Detection Patterns
SQL_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Possible SQL injection - string concatenation", re.compile(r"(?i)(execute|exec|query|cursor\.execute)\s*\(\s*['\"].*?\+.*?['\"]")),
    ("Possible SQL injection - f-string", re.compile(r"(?i)(execute|exec|query|cursor\.execute)\s*\(\s*f['\"].*?\{.*?\}.*?['\"]")),
    ("Possible SQL injection - format", re.compile(r"(?i)(execute|exec|query|cursor\.execute)\s*\(\s*['\"].*?\.format\(")),
    ("Raw SQL with user input", re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).*?request\.|request\..*?(GET|POST|PARAM|ARGS)")),
    ("SQL in template (Jinja2)", re.compile(r"(?i)\{\%.*?(SELECT|INSERT|UPDATE|DELETE|DROP).*?\%\}")),
]

# Authentication Security Patterns
AUTH_INSECURE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Hardcoded password", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]")),
    ("Hardcoded username", re.compile(r"(?i)(username|user|login)\s*[:=]\s*['\"][^'\"]{3,}['\"]")),
    ("Weak password hashing (MD5)", re.compile(r"(?i)hashlib\.md5\(|hashlib\.new\(['\"]md5['\"]")),
    ("Weak password hashing (SHA1)", re.compile(r"(?i)hashlib\.sha1\(|hashlib\.new\(['\"]sha1['\"]")),
    ("Insecure password comparison", re.compile(r"(?i)(==\s*|!=)(password|passwd|pwd)")),
    ("Missing authentication check", re.compile(r"(?i)@app\.route\([^)]*\)\s*\n\s*def\s+\w+\s*\([^)]*\):\s*\n\s*(?!.*(?:login|auth|require|authenticated))")),
    ("Disabled authentication", re.compile(r"(?i)(auth|authentication|login)\s*=\s*False")),
    ("JWT without expiration", re.compile(r"(?i)jwt\.encode\([^)]*expires_delta\s*=\s*None")),
]

# Path Traversal Detection Patterns
PATH_TRAVERSAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Path traversal risk - os.path.join with user input", re.compile(r"(?i)os\.path\.join\([^)]*request\.|request\.")),
    ("Path traversal risk - open with user input", re.compile(r"(?i)open\([^)]*request\.|request\..*?(GET|POST|PARAM|ARGS)")),
    ("Path traversal risk - os.path.abspath", re.compile(r"(?i)os\.path\.abspath\([^)]*request\.")),
    ("Directory traversal with ..", re.compile(r"(?i)(\.\./|\.\.\\\\).*?(request\.|file|path)")),
    ("Flask send_file with user input", re.compile(r"(?i)send_file\([^)]*request\.")),
]

# Command Injection Patterns
CMD_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Command injection - os.system", re.compile(r"(?i)os\.system\([^)]*(\+|\.|f['\"]|format\()")),
    ("Command injection - subprocess with shell=True", re.compile(r"(?i)subprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True")),
    ("Command injection - os.popen", re.compile(r"(?i)os\.popen\(")),
    ("Command injection - subprocess with user input", re.compile(r"(?i)subprocess\.(run|call|Popen)\([^)]*request\.")),
    ("Command injection - eval with user input", re.compile(r"(?i)eval\([^)]*request\.")),
    ("Command injection - exec with user input", re.compile(r"(?i)exec\([^)]*request\.")),
]

# XSS Vulnerability Patterns
XSS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("XSS risk - render_template_string", re.compile(r"(?i)render_template_string\(")),
    ("XSS risk - markupsafe with user input", re.compile(r"(?i)markupsafe\.Markup\([^)]*request\.")),
    ("XSS risk - HTML without escaping", re.compile(r"(?i)(\.unescape\(|Markup\.unescape\()")),
    ("XSS risk - innerHTML assignment", re.compile(r"(?i)(innerHTML|html\s*=\s*).*?request\.")),
    ("XSS risk - document.write", re.compile(r"(?i)document\.write\([^)]*request\.")),
    ("XSS risk - dangerouslySetInnerHTML", re.compile(r"(?i)dangerouslySetInnerHTML\s*=\s*\{.*?request")),
]

# Insecure Deserialization Patterns
DESERIALIZATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Insecure deserialization - pickle", re.compile(r"(?i)pickle\.loads?\(")),
    ("Insecure deserialization - yaml unsafe", re.compile(r"(?i)yaml\.(unsafe_load|load)\(")),
    ("Insecure deserialization - eval exec", re.compile(r"(?i)(eval|exec)\(")),
    ("Insecure deserialization - marshal", re.compile(r"(?i)marshal\.loads?\(")),
]

# Security Headers Missing Patterns
SECURITY_HEADERS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Missing security headers", re.compile(r"(?i)response\.headers\[(['\"]Content-Security-Policy['\"]|['\"]X-Frame-Options['\"]|['\"]X-Content-Type-Options['\"])")),
]


def run_review(
    *,
    gh: GitHubClient,
    llm: LLMClient,
    db_path: str,
    repo_full_name: str,
    pr_number: int,
    base_branch: str,
    max_diff_chars: int,
    post_comment: bool = True,
) -> dict[str, Any]:
    init_db(db_path)
    pr = gh.get_pull(repo_full_name, pr_number)
    pr_base = pr.get("base", {}).get("ref")
    pr_head_sha = pr.get("head", {}).get("sha")

    files = gh.list_pull_files(repo_full_name, pr_number)
    diff_text, diff_meta = _build_diff_text(files, max_chars=max_diff_chars)

    static_findings = _static_checks(files, diff_text)

    style_notes = get_style_notes(db_path)
    llm_result = llm.review_diff(
        repo=repo_full_name,
        pr_number=pr_number,
        base_branch=base_branch,
        diff_text=diff_text,
        style_notes=style_notes,
    )

    llm_findings = _parse_llm_findings(llm_result.parsed)

    findings: list[Finding] = []
    findings.extend(static_findings)
    findings.extend(llm_findings)

    # ====== FEATURE 2: Calculate PR Scores ======
    findings_dicts = [f.__dict__ for f in findings]
    pr_scores = calculate_all_scores(findings_dicts, files, diff_text)
    scores_markdown = format_scores_markdown(pr_scores)

    comment_body = format_pr_comment(
        repo_full_name=repo_full_name,
        pr_number=pr_number,
        base_branch=base_branch,
        pr_base_ref=pr_base,
        diff_meta=diff_meta,
        findings=findings,
        llm_provider=llm.provider,
        llm_model=llm.model,
        llm_parse_ok=llm_result.parsed is not None,
        scores=pr_scores,
    )

    comment_id: Optional[int] = None
    if post_comment:
        created = gh.create_issue_comment(repo_full_name, pr_number, comment_body)
        comment_id = created.get("id")

    findings_payload = {
        "head_sha": pr_head_sha,
        "diff_meta": diff_meta,
        "static_count": len(static_findings),
        "llm_parse_ok": llm_result.parsed is not None,
        "llm_raw": llm_result.raw_text if llm_result.parsed is None else None,
        "findings": findings_dicts,
        # Store scores in findings payload
        "scores": {
            "risk_level": pr_scores.risk_level,
            "risk_score": pr_scores.risk_score,
            "complexity_score": pr_scores.complexity_score,
            "security_score": pr_scores.security_score,
            "maintainability_score": pr_scores.maintainability_score,
            "summary": pr_scores.summary,
        },
    }
    upsert_review(db_path, repo_full_name, pr_number, comment_id, findings_payload)

    # ====== FEATURE 4: Record Metrics for Toil Reduction ======
    record_metric(db_path, "review_completed", 1, repo_full_name, pr_number)
    lines_reviewed = diff_meta.get('chars_used', 0) // 50
    if lines_reviewed > 0:
        record_metric(db_path, "lines_reviewed", lines_reviewed, repo_full_name, pr_number)
    security_issues = sum(1 for f in findings if f.severity in ('critical', 'high'))
    if security_issues > 0:
        record_metric(db_path, "security_issue_found", security_issues, repo_full_name, pr_number)
    record_metric(db_path, "time_saved_minutes", 5, repo_full_name, pr_number)

    return {
        "repo": repo_full_name,
        "pr_number": pr_number,
        "comment_id": comment_id,
        "findings_total": len(findings),
        "static_findings": len(static_findings),
        "llm_findings": len(llm_findings),
        "base_ref": pr_base,
        "head_sha": pr_head_sha,
        "scores": pr_scores.__dict__,
    }


def format_pr_comment(
    *,
    repo_full_name: str,
    pr_number: int,
    base_branch: str,
    pr_base_ref: Optional[str],
    diff_meta: dict[str, Any],
    findings: list[Finding],
    llm_provider: str,
    llm_model: str,
    llm_parse_ok: bool,
    scores: Any = None,
) -> str:
    # Import PRScores type for type checking
    from .scoring import PRScores
    
    header = [
        "<!-- ai-pr-guard:review -->",
        f"## Sentinel review for `{repo_full_name}` PR #{pr_number}",
        "",
    ]
    
    # ====== FEATURE 2: Add Scorecard to PR Comment ======
    if scores is not None and isinstance(scores, PRScores):
        header.extend([
            "### 📊 PR Scorecard",
            "",
            f"| 🛡️ Security | 📈 Complexity | 🔧 Maintainability | 🔴 Risk |",
            "|:---:|:---:|:---:|:---:|",
            f"| `{scores.security_score}/100` | `{scores.complexity_score}/100` | `{scores.maintainability_score}/100` | `{scores.risk_score}/100` ({scores.risk_level.upper()}) |",
            "",
        ])
    
    header.extend([
        f"- **Configured base branch**: `{base_branch}`",
        f"- **PR base branch**: `{pr_base_ref}`" if pr_base_ref else "- **PR base branch**: (unknown)",
        f"- **Files changed**: {diff_meta.get('files_changed', 0)}",
        f"- **Patch chars sent to LLM**: {diff_meta.get('chars_used', 0)} / {diff_meta.get('max_chars', 0)}",
        f"- **LLM**: `{llm_provider}` / `{llm_model}` (parsed JSON: {'yes' if llm_parse_ok else 'no'})",
        "",
        "### Findings (check items you agree with to help the agent learn your team style)",
        "",
    ])

    if not findings:
        header.append("_No high-signal issues detected in the provided diff._")
        return "\n".join(header).strip() + "\n"

    lines: list[str] = header
    for f in findings[:40]:
        title = f"[{f.severity.upper()}] {f.title}".strip()
        details = _one_line(f.details)
        suggestion = _one_line(f.suggestion)
        style_rule = _one_line(f.style_rule)
        lines.append(f"- [ ] ({f.id}) **{title}** — {details}")
        if suggestion:
            lines.append(f"  - **Suggestion**: {suggestion}")
        if style_rule:
            lines.append(f"  - **Style rule**: `{style_rule}`")
        lines.append(f"  - **Source**: `{f.source}`")
        lines.append("")

    lines.append("### How to provide feedback")
    lines.append("- Check items you agree with, then run `python -m ai_pr_guard sync-feedback <PR_NUMBER>`.")
    lines.append("- The agent will store accepted style rules locally (SQLite) and use them in future reviews.")
    return "\n".join(lines).strip() + "\n"


def extract_checked_style_rules(comment_body: str) -> list[str]:
    """
    Looks for checklist entries that are checked and extracts the `Style rule` line.
    This is intentionally simple and robust.
    """
    accepted: list[str] = []
    lines = comment_body.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("- [x]") or line.lstrip().startswith("- [X]"):
            # scan forward a few lines for "Style rule"
            for j in range(i + 1, min(i + 6, len(lines))):
                m = re.search(r"`([^`]+)`", lines[j])
                if "Style rule" in lines[j] and m:
                    accepted.append(m.group(1).strip())
                    break
        i += 1
    # de-dupe, preserve order
    seen = set()
    out: list[str] = []
    for r in accepted:
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _build_diff_text(files: list[dict[str, Any]], max_chars: int) -> tuple[str, dict[str, Any]]:
    chunks: list[str] = []
    used = 0
    for f in files:
        filename = f.get("filename", "")
        status = f.get("status", "")
        patch = f.get("patch") or ""
        header = f"\n=== {filename} ({status}) ===\n"
        body = patch.strip() if patch else "(no patch available from GitHub for this file)"
        chunk = header + body + "\n"
        if used + len(chunk) > max_chars:
            remaining = max_chars - used
            if remaining <= 0:
                break
            chunk = chunk[:remaining] + "\n... (truncated)\n"
            chunks.append(chunk)
            used += len(chunk)
            break
        chunks.append(chunk)
        used += len(chunk)
    text = "".join(chunks).strip() + "\n"
    meta = {"files_changed": len(files), "chars_used": used, "max_chars": max_chars}
    return text, meta


def _static_checks(files: list[dict[str, Any]], diff_text: str) -> list[Finding]:
    findings: list[Finding] = []

    # ====== 1. SECRETS DETECTION (Critical) ======
    for label, pat in SECRET_PATTERNS:
        if pat.search(diff_text):
            findings.append(
                Finding(
                    id=f"S-{len(findings)+1}",
                    severity="critical",
                    title=f"Possible secret committed: {label}",
                    details="A pattern that looks like a secret/private credential appeared in the diff.",
                    suggestion="Remove the secret from git history, rotate it, and use a secret manager or CI secrets.",
                    style_rule="Never commit secrets; use a secret manager/CI secrets.",
                    source="static",
                )
            )

    # ====== 2. SQL INJECTION DETECTION (Critical) ======
    for label, pat in SQL_INJECTION_PATTERNS:
        if pat.search(diff_text):
            findings.append(
                Finding(
                    id=f"S-{len(findings)+1}",
                    severity="critical",
                    title=f"SQL Injection Risk: {label}",
                    details="This pattern may allow SQL injection attacks if user input is not properly sanitized.",
                    suggestion="Use parameterized queries or an ORM. Never concatenate user input into SQL strings.",
                    style_rule="Use parameterized queries; avoid string concatenation in SQL.",
                    source="static",
                )
            )

    # ====== 3. AUTHENTICATION SECURITY (High) ======
    for label, pat in AUTH_INSECURE_PATTERNS:
        if pat.search(diff_text):
            severity = "high"
            if "Weak password" in label or "JWT without" in label:
                severity = "critical"
            findings.append(
                Finding(
                    id=f"S-{len(findings)+1}",
                    severity=severity,
                    title=f"Authentication Security: {label}",
                    details="This pattern may introduce authentication vulnerabilities.",
                    suggestion="Use secure password hashing (bcrypt/argon2), proper auth checks, and secure JWT handling.",
                    style_rule="Use secure authentication practices; never hardcode credentials.",
                    source="static",
                )
            )

    # ====== 4. PATH TRAVERSAL (High) ======
    for label, pat in PATH_TRAVERSAL_PATTERNS:
        if pat.search(diff_text):
            findings.append(
                Finding(
                    id=f"S-{len(findings)+1}",
                    severity="high",
                    title=f"Path Traversal Risk: {label}",
                    details="This pattern may allow attackers to access files outside the web root.",
                    suggestion="Validate and sanitize file paths. Use allowlists for permitted paths.",
                    style_rule="Validate file paths; avoid user input in file operations.",
                    source="static",
                )
            )

    # ====== 5. COMMAND INJECTION (Critical) ======
    for label, pat in CMD_INJECTION_PATTERNS:
        if pat.search(diff_text):
            findings.append(
                Finding(
                    id=f"S-{len(findings)+1}",
                    severity="critical",
                    title=f"Command Injection Risk: {label}",
                    details="This pattern may allow attackers to execute arbitrary commands.",
                    suggestion="Avoid shell=True. Use subprocess with argument lists. Sanitize all user input.",
                    style_rule="Never use user input in shell commands; use argument lists.",
                    source="static",
                )
            )

    # ====== 6. XSS VULNERABILITIES (High) ======
    for label, pat in XSS_PATTERNS:
        if pat.search(diff_text):
            findings.append(
                Finding(
                    id=f"S-{len(findings)+1}",
                    severity="high",
                    title=f"XSS Vulnerability: {label}",
                    details="This pattern may introduce cross-site scripting (XSS) vulnerabilities.",
                    suggestion="Use template engines with auto-escaping. Never render raw HTML with user input.",
                    style_rule="Always escape user input in HTML contexts.",
                    source="static",
                )
            )

    # ====== 7. INSECURE DESERIALIZATION (Critical) ======
    for label, pat in DESERIALIZATION_PATTERNS:
        if pat.search(diff_text):
            findings.append(
                Finding(
                    id=f"S-{len(findings)+1}",
                    severity="critical",
                    title=f"Insecure Deserialization: {label}",
                    details="This pattern may allow remote code execution through insecure deserialization.",
                    suggestion="Use safe serialization formats (JSON). Avoid pickle/yaml with untrusted data.",
                    style_rule="Use safe serialization; avoid pickle/yaml with external data.",
                    source="static",
                )
            )

    # ====== 8. Dangerous file types ======
    for f in files:
        name = (f.get("filename") or "").lower()
        if name.endswith(".env") or name.endswith(".pem") or name.endswith(".key") or name.endswith("id_rsa"):
            findings.append(
                Finding(
                    id=f"S-{len(findings)+1}",
                    severity="high",
                    title=f"Sensitive file in PR: {f.get('filename')}",
                    details="This file type commonly contains secrets or private keys.",
                    suggestion="Confirm it is safe to commit; otherwise remove and rotate any exposed credentials.",
                    style_rule="Avoid committing sensitive key/secret files to the repo.",
                    source="static",
                )
            )

    # ====== 9. TODO / FIXME (Low) ======
    if re.search(r"(?i)\b(TODO|FIXME)\b", diff_text):
        findings.append(
            Finding(
                id=f"S-{len(findings)+1}",
                severity="low",
                title="TODO/FIXME markers added",
                details="The diff includes TODO/FIXME which often indicates unfinished work or follow-up debt.",
                suggestion="Either address before merge, or create a tracked ticket and reference it in the TODO.",
                style_rule="Avoid untracked TODOs; link them to an issue/ticket.",
                source="static",
            )
        )

    return findings


def _parse_llm_findings(parsed: Optional[dict[str, Any]]) -> list[Finding]:
    if not parsed or not isinstance(parsed, dict):
        return []
    raw = parsed.get("findings")
    if not isinstance(raw, list):
        return []
    out: list[Finding] = []
    for it in raw:
        if not isinstance(it, dict):
            continue
        fid = str(it.get("id") or f"F-{len(out)+1}")
        out.append(
            Finding(
                id=fid,
                severity=str(it.get("severity") or "low"),
                title=str(it.get("title") or "").strip()[:200],
                details=str(it.get("details") or "").strip(),
                suggestion=str(it.get("suggestion") or "").strip(),
                style_rule=str(it.get("style_rule") or "").strip(),
                source="llm",
            )
        )
    return out


def _one_line(s: str, max_len: int = 240) -> str:
    s = (s or "").strip()
    s = re.sub(r"\s+", " ", s)
    if len(s) > max_len:
        return s[: max_len - 1].rstrip() + "…"
    return s


def safe_wrap(text: str, width: int = 100) -> str:
    return "\n".join(textwrap.wrap(text, width=width))
