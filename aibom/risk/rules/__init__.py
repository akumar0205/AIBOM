from __future__ import annotations

from aibom.risk.rules.base import RiskRule
from aibom.risk.rules.exfil_surface import ExfilSurfaceRule
from aibom.risk.rules.internet_egress import InternetEgressRule
from aibom.risk.rules.model_version_drift import ModelVersionDriftRule
from aibom.risk.rules.prompt_injection_surface import PromptInjectionSurfaceRule
from aibom.risk.rules.prompt_logging import PromptLoggingRule
from aibom.risk.rules.retrieval_augmentation import RetrievalAugmentationRule
from aibom.risk.rules.secret_exposure import SecretExposureRule
from aibom.risk.rules.third_party_provider import ThirdPartyProviderRule
from aibom.risk.rules.tool_execution import ToolExecutionRule
from aibom.risk.rules.unsupported_provider import UnsupportedProviderRule


def load_builtin_rulepack() -> dict[str, RiskRule]:
    rules = [
        ThirdPartyProviderRule(),
        ExfilSurfaceRule(),
        PromptInjectionSurfaceRule(),
        SecretExposureRule(),
        InternetEgressRule(),
        RetrievalAugmentationRule(),
        ToolExecutionRule(),
        PromptLoggingRule(),
        ModelVersionDriftRule(),
        UnsupportedProviderRule(),
    ]
    return {rule.metadata.base_rule_id: rule for rule in rules}
