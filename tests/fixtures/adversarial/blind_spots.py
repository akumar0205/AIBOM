"""Known blind spot (documented, not detected): raw HTTP to a provider.

No SDK constructor, import alias, or config key references a model here, so
static detectors intentionally report nothing. This fixture quantifies the
gap for the detector benchmark instead of silently ignoring it.
"""

import requests

resp = requests.post(
    "https://api.openai.com/v1/chat/completions",
    headers={"Authorization": "Bearer sk-test"},
    json={"model": "gpt-4o-mini", "messages": []},
)
