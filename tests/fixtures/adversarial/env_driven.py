"""Adversarial fixture: env-driven provider selection."""

import os

from langchain_openai import ChatOpenAI

SELECTED_MODEL = os.environ.get("APP_MODEL", "gpt-4o-mini")

llm = ChatOpenAI(model=SELECTED_MODEL)
