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


def trend_diff_aibom(history: list[dict[str, Any]], current: dict[str, Any]) -> dict[str, Any]:
    latest = history[-1] if history else {"models": [], "tools": [], "datasets": []}
    pairwise = diff_aibom(latest, current)

    all_seen = {"models": set(), "tools": set(), "datasets": set()}
    for snapshot in history:
        all_seen["models"].update(item.get("type", "") for item in snapshot.get("models", []))
        all_seen["tools"].update(item.get("name", "") for item in snapshot.get("tools", []))
        all_seen["datasets"].update(item.get("type", "") for item in snapshot.get("datasets", []))

    novel = {
        "models": [
            item
            for item in current.get("models", [])
            if item.get("type", "") not in all_seen["models"]
        ],
        "tools": [
            item
            for item in current.get("tools", [])
            if item.get("name", "") not in all_seen["tools"]
        ],
        "datasets": [
            item
            for item in current.get("datasets", [])
            if item.get("type", "") not in all_seen["datasets"]
        ],
    }

    return {
        "pairwise": pairwise,
        "trend": {
            "history_window": len(history),
            "novel_since_window": novel,
            "change_counts": {
                "added": sum(len(v) for v in pairwise["added"].values()),
                "removed": sum(len(v) for v in pairwise["removed"].values()),
                "changed": sum(len(v) for v in pairwise["changed"].values()),
            },
        },
    }


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
