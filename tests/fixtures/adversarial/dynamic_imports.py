"""Adversarial fixture: dynamic imports evade static import tracking."""

import importlib

openai = importlib.import_module("openai")
client = openai.OpenAI()
