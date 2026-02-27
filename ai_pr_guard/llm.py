from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True)
class LLMResult:
    raw_text: str
    parsed: Optional[dict[str, Any]]


class LLMClient:
    def __init__(self, provider: str, api_key: Optional[str], base_url: Optional[str], model: str) -> None:
        self.provider = (provider or "openai").strip().lower()
        self.api_key = api_key
        self.base_url = base_url
        self.model = model

        self._client = None
        if self.provider == "ollama":
            # Use the official ollama Python package
            try:
                import ollama
                self._client = ollama
            except Exception as e:
                raise LLMError(f"ollama package not installed or failed to import: {e}") from e
        elif self.provider == "openai":
            if not self.api_key:
                raise LLMError("OPENAI_API_KEY is missing (set it in .env or environment).")
            try:
                from openai import OpenAI  # type: ignore
            except Exception as e:
                raise LLMError(f"openai package not installed or failed to import: {e}") from e
            kwargs = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = OpenAI(**kwargs)
        elif self.provider == "mock":
            self._client = None
        else:
            raise LLMError(f"Unsupported LLM_PROVIDER '{self.provider}'. Use 'openai', 'ollama', or 'mock'.")

    def review_diff(self, *, repo: str, pr_number: int, base_branch: str, diff_text: str, style_notes: list[str]) -> LLMResult:
        if self.provider == "mock":
            dummy = {
                "summary": "Mock review: replace LLM_PROVIDER=mock with openai for real reviews.",
                "findings": [
                    {
                        "id": "F-1",
                        "severity": "medium",
                        "title": "Add tests for changed logic",
                        "details": "No test changes detected alongside code changes.",
                        "suggestion": "Add/extend unit tests to cover new behavior and edge cases.",
                        "style_rule": "Prefer adding tests when changing logic.",
                    }
                ],
            }
            return LLMResult(raw_text=json.dumps(dummy, indent=2), parsed=dummy)

        system = (
            "You are an expert code reviewer and security engineer. "
            "Review the provided PR diff with high precision. "
            "Prioritize: correctness bugs, security issues, data validation, authz/authn, "
            "error handling, concurrency, and maintainability. "
            "Be concrete and reference what you saw in the diff. "
            "Do NOT invent files or code not present."
        )

        style_block = ""
        if style_notes:
            style_block = (
                "\n\nTeam style memory (learned preferences; follow these when making suggestions):\n"
                + "\n".join([f"- {s}" for s in style_notes])
            )

        user = (
            f"Repo: {repo}\nPR: #{pr_number}\nBase branch: {base_branch}"
            f"{style_block}\n\n"
            "Return STRICT JSON with this shape:\n"
            "{\n"
            '  "summary": string,\n'
            '  "findings": [\n'
            "    {\n"
            '      "id": string,\n'
            '      "severity": "low"|"medium"|"high"|"critical",\n'
            '      "title": string,\n'
            '      "details": string,\n'
            '      "suggestion": string,\n'
            '      "style_rule": string\n'
            "    }\n"
            "  ]\n"
            "}\n\n"
            "Rules:\n"
            "- Findings must be actionable and grounded in diff.\n"
            "- Include 0-12 findings; prefer fewer, higher-signal items.\n"
            "- style_rule should be a reusable preference (short).\n\n"
            "PR diff:\n"
            "-----\n"
            f"{diff_text}\n"
            "-----\n"
        )

        assert self._client is not None
        try:
            if self.provider == "ollama":
                # Use ollama.chat() API
                resp = self._client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    options={"temperature": 0.2},
                )
                text = (resp["message"]["content"] or "").strip()
            else:
                # Use OpenAI chat completions API
                resp = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=0.2,
                )
                text = (resp.choices[0].message.content or "").strip()
        except Exception as e:
            raise LLMError(f"LLM call failed: {e}") from e

        parsed: Optional[dict[str, Any]] = None
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
        return LLMResult(raw_text=text, parsed=parsed)
