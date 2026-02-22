from __future__ import annotations

from typing import Any

EXTERNAL_PROVIDER_MODELS = {"OpenAI", "ChatOpenAI", "ChatAnthropic"}
EXFIL_TOOLS = {"Requests", "ReadFileTool", "WriteFileTool", "SerpAPI"}


def generate_risk_findings(aibom: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for model in aibom.get("models", []):
        if model.get("type") in EXTERNAL_PROVIDER_MODELS:
            findings.append(
                {
                    "id": f"third-party:{model['type']}:{model.get('source_file','')}",
                    "category": "third-party dependency",
                    "owasp_llm": "LLM07 Insecure Plugin Design",
                    "severity": "medium",
                    "rationale": "External model provider detected.",
                    "heuristic": "true",
                }
            )
    for tool in aibom.get("tools", []):
        if tool.get("name") in EXFIL_TOOLS:
            findings.append(
                {
                    "id": f"exfil:{tool['name']}:{tool.get('source_file','')}",
                    "category": "exfil surface",
                    "owasp_llm": "LLM06 Sensitive Information Disclosure",
                    "severity": "high",
                    "rationale": "Tool may read/write data or access web.",
                    "heuristic": "true",
                }
            )
    if aibom.get("prompts"):
        findings.append(
            {
                "id": "prompt-injection-surface",
                "category": "prompt injection surface",
                "owasp_llm": "LLM01 Prompt Injection",
                "severity": "medium",
                "rationale": "Prompt templates detected; review source trust boundaries.",
                "heuristic": "true",
            }
        )
    return sorted(findings, key=lambda x: x["id"])
