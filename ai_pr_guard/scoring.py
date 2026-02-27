"""
PR Risk Scoring System

Provides comprehensive scoring for PR reviews:
- Risk Score (Low/Medium/High/Critical)
- Complexity Score
- Security Score
- Maintainability Score
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PRScores:
    """Container for all PR scores."""
    risk_level: str  # "low", "medium", "high", "critical"
    risk_score: int  # 0-100
    complexity_score: int  # 0-100
    security_score: int  # 0-100
    maintainability_score: int  # 0-100
    summary: dict[str, Any]


def calculate_risk_score(findings: list[dict[str, Any]]) -> tuple[str, int]:
    """
    Calculate overall risk level based on findings.
    
    Returns:
        Tuple of (risk_level, risk_score)
    """
    if not findings:
        return ("low", 10)
    
    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    # Calculate weighted risk score
    # Critical = 40 points each, High = 25, Medium = 10, Low = 3
    risk_score = (
        severity_counts["critical"] * 40 +
        severity_counts["high"] * 25 +
        severity_counts["medium"] * 10 +
        severity_counts["low"] * 3
    )
    
    # Cap at 100
    risk_score = min(100, risk_score)
    
    # Determine risk level
    if risk_score >= 80:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 20:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return (risk_level, risk_score)


def calculate_complexity_score(files: list[dict[str, Any]], diff_text: str) -> tuple[int, dict[str, Any]]:
    """
    Calculate complexity score based on:
    - Number of files changed
    - Total lines changed
    - File types involved
    - Language complexity
    
    Returns:
        Tuple of (complexity_score, summary_dict)
    """
    file_count = len(files)
    
    # Count lines changed
    total_additions = 0
    total_deletions = 0
    language_counts: dict[str, int] = {}
    
    for f in files:
        additions = f.get("additions", 0)
        deletions = f.get("deletions", 0)
        total_additions += additions
        total_deletions += deletions
        
        # Detect language from filename
        filename = f.get("filename", "")
        ext = filename.split(".")[-1].lower() if "." in filename else ""
        lang_map = {
            "py": "Python", "js": "JavaScript", "ts": "TypeScript",
            "java": "Java", "go": "Go", "rs": "Rust", "cpp": "C++",
            "c": "C", "cs": "C#", "rb": "Ruby", "php": "PHP",
            "html": "HTML", "css": "CSS", "scss": "SCSS",
            "sql": "SQL", "json": "JSON", "yaml": "YAML", "yml": "YAML",
            "md": "Markdown", "sh": "Shell", "bash": "Shell"
        }
        lang = lang_map.get(ext, "Other")
        language_counts[lang] = language_counts.get(lang, 0) + 1
    
    total_lines = total_additions + total_deletions
    
    # Calculate complexity factors
    # More files = higher complexity
    file_factor = min(30, file_count * 3)
    
    # More lines = higher complexity  
    lines_factor = min(30, total_lines // 20)
    
    # Multiple languages = higher complexity
    lang_factor = min(20, len(language_counts) * 5)
    
    # High ratio of deletions (code removal) might indicate refactoring
    deletion_ratio = total_deletions / max(1, total_lines)
    refactor_factor = 10 if deletion_ratio > 0.3 else 5
    
    # High additions might indicate new features (moderate complexity)
    addition_factor = 10 if total_additions > 200 else 5
    
    complexity_score = file_factor + lines_factor + lang_factor + refactor_factor + addition_factor
    complexity_score = min(100, complexity_score)
    
    summary = {
        "files_changed": file_count,
        "additions": total_additions,
        "deletions": total_deletions,
        "total_lines": total_lines,
        "languages": language_counts,
        "deletion_ratio": round(deletion_ratio, 2)
    }
    
    return (complexity_score, summary)


def calculate_security_score(findings: list[dict[str, Any]]) -> tuple[int, dict[str, Any]]:
    """
    Calculate security score based on security-related findings.
    
    Returns:
        Tuple of (security_score, summary_dict)
    """
    if not findings:
        return (100, {"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": True})
    
    # Security-related categories
    security_categories = [
        "secret", "sql injection", "authentication", "path traversal",
        "command injection", "xss", "deserialization", "injection",
        "insecure", "vulnerability"
    ]
    
    # Count security findings by severity
    sec_critical = 0
    sec_high = 0
    sec_medium = 0
    sec_low = 0
    
    for f in findings:
        title = (f.get("title") or "").lower()
        details = (f.get("details") or "").lower()
        severity = (f.get("severity") or "low").lower()
        
        # Check if this is a security finding
        is_security = any(cat in title or cat in details for cat in security_categories)
        
        if is_security:
            if severity == "critical":
                sec_critical += 1
            elif severity == "high":
                sec_high += 1
            elif severity == "medium":
                sec_medium += 1
            else:
                sec_low += 1
    
    # Calculate security score (starts at 100, subtracts based on findings)
    # Each critical = -40, high = -20, medium = -10, low = -3
    deductions = sec_critical * 40 + sec_high * 20 + sec_medium * 10 + sec_low * 3
    security_score = max(0, 100 - deductions)
    
    summary = {
        "critical": sec_critical,
        "high": sec_high,
        "medium": sec_medium,
        "low": sec_low,
        "passed": security_score >= 80
    }
    
    return (security_score, summary)


def calculate_maintainability_score(findings: list[dict[str, Any]]) -> tuple[int, dict[str, Any]]:
    """
    Calculate maintainability score based on:
    - Code quality issues
    - Technical debt
    - Style violations
    
    Returns:
        Tuple of (maintainability_score, summary_dict)
    """
    # Non-security related categories
    maintainability_indicators = [
        "todo", "fixme", "code smell", "complex", "duplicate",
        "dead code", "naming", "convention", "style", "format"
    ]
    
    # Count maintainability issues
    issues_found = 0
    for f in findings:
        title = (f.get("title") or "").lower()
        details = (f.get("details") or "").lower()
        style_rule = (f.get("style_rule") or "").lower()
        
        if any(ind in title or ind in details or ind in style_rule for ind in maintainability_indicators):
            issues_found += 1
    
    # Start at 80 (baseline), subtract for issues
    # Good maintainability is around 80-100
    base_score = 80
    deductions = issues_found * 8
    maintainability_score = max(0, base_score - deductions)
    
    summary = {
        "issues_found": issues_found,
        "score_description": _get_maintainability_description(maintainability_score)
    }
    
    return (maintainability_score, summary)


def _get_maintainability_description(score: int) -> str:
    """Get human-readable description of maintainability score."""
    if score >= 80:
        return "Excellent - Code is highly maintainable"
    elif score >= 60:
        return "Good - Minor improvements possible"
    elif score >= 40:
        return "Fair - Some technical debt present"
    elif score >= 20:
        return "Poor - Significant refactoring recommended"
    else:
        return "Critical - Major maintainability issues"


def calculate_all_scores(
    findings: list[dict[str, Any]],
    files: list[dict[str, Any]],
    diff_text: str
) -> PRScores:
    """
    Calculate all PR scores and return comprehensive results.
    
    Args:
        findings: List of finding dictionaries from review
        files: List of file change dictionaries from GitHub
        diff_text: The diff text that was analyzed
    
    Returns:
        PRScores dataclass with all calculated scores
    """
    # Calculate individual scores
    risk_level, risk_score = calculate_risk_score(findings)
    complexity_score, complexity_summary = calculate_complexity_score(files, diff_text)
    security_score, security_summary = calculate_security_score(findings)
    maintainability_score, maintainability_summary = calculate_maintainability_score(findings)
    
    # Build summary
    summary = {
        "complexity": complexity_summary,
        "security": security_summary,
        "maintainability": maintainability_summary,
        "total_findings": len(findings),
        "risk_factors": {
            "critical_findings": security_summary.get("critical", 0),
            "high_findings": security_summary.get("high", 0)
        }
    }
    
    return PRScores(
        risk_level=risk_level,
        risk_score=risk_score,
        complexity_score=complexity_score,
        security_score=security_score,
        maintainability_score=maintainability_score,
        summary=summary
    )


def get_score_badge_html(score: int, label: str) -> str:
    """Generate HTML badge for a score."""
    if score >= 80:
        color = "#10b981"  # Green
    elif score >= 60:
        color = "#3b82f6"  # Blue
    elif score >= 40:
        color = "#f59e0b"  # Yellow/Orange
    else:
        color = "#ef4444"  # Red
    
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px;">{label}: {score}</span>'


def format_scores_markdown(scores: PRScores) -> str:
    """Format scores as Markdown for PR comments."""
    lines = [
        "### 📊 PR Scorecard",
        "",
        f"| Metric | Score | Level |",
        "|--------|-------|-------|",
        f"| 🔴 Risk Score | {scores.risk_score}/100 | {scores.risk_level.upper()} |",
        f"| 📈 Complexity | {scores.complexity_score}/100 | {_get_level(scores.complexity_score)} |",
        f"| 🛡️ Security | {scores.security_score}/100 | {_get_level(scores.security_score)} |",
        f"| 🔧 Maintainability | {scores.maintainability_score}/100 | {_get_level(scores.maintainability_score)} |",
        "",
    ]
    
    # Add summary
    sec = scores.summary.get("security", {})
    if sec.get("critical", 0) > 0 or sec.get("high", 0) > 0:
        lines.append(f"⚠️ **Security Alert**: {sec.get('critical', 0)} critical, {sec.get('high', 0)} high severity issues")
    
    return "\n".join(lines)


def _get_level(score: int) -> str:
    """Get level name for score."""
    if score >= 80:
        return "Excellent"
    elif score >= 60:
        return "Good"
    elif score >= 40:
        return "Fair"
    else:
        return "Needs Work"
