from __future__ import annotations

from typing import Any


def _index(items: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    return {str(i.get(key, "")): i for i in items}


def diff_aibom(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    sections = {"models": "type", "tools": "name", "datasets": "type"}
    out: dict[str, Any] = {"added": {}, "removed": {}, "changed": {}}
    for sec, k in sections.items():
        old_i = _index(old.get(sec, []), k)
        new_i = _index(new.get(sec, []), k)
        added = [new_i[x] for x in sorted(new_i.keys() - old_i.keys())]
        removed = [old_i[x] for x in sorted(old_i.keys() - new_i.keys())]
        changed = [
            {"before": old_i[x], "after": new_i[x]}
            for x in sorted(new_i.keys() & old_i.keys())
            if old_i[x] != new_i[x]
        ]
        out["added"][sec] = added
        out["removed"][sec] = removed
        out["changed"][sec] = changed
    return out


def gate_failures(diff: dict[str, Any], fail_on: set[str]) -> list[str]:
    failures: list[str] = []
    if "new-model" in fail_on and diff["added"]["models"]:
        failures.append("new-model")
    if "new-tool" in fail_on and diff["added"]["tools"]:
        failures.append("new-tool")
    if "new-external-provider" in fail_on:
        for item in diff["added"]["models"]:
            if item.get("type") in {"OpenAI", "ChatOpenAI", "ChatAnthropic"}:
                failures.append("new-external-provider")
                break
    return failures
