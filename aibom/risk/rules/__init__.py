from __future__ import annotations

from aibom.risk.rules.base import RiskRule
from aibom.risk.rules.exfil_surface import ExfilSurfaceRule
from aibom.risk.rules.prompt_injection_surface import PromptInjectionSurfaceRule
from aibom.risk.rules.third_party_provider import ThirdPartyProviderRule


def load_builtin_rulepack() -> dict[str, RiskRule]:
    rules = [ThirdPartyProviderRule(), ExfilSurfaceRule(), PromptInjectionSurfaceRule()]
    return {rule.metadata.base_rule_id: rule for rule in rules}
