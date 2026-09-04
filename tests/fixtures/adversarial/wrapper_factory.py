"""Adversarial fixture: wrapper factories hide direct constructor calls."""

import os

from langchain_openai import ChatOpenAI

MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o-mini")


def build_llm(model: str = MODEL_NAME):
    return ChatOpenAI(model=model)


def make_primary():
    constructor = ChatOpenAI
    return constructor(model="gpt-4o")


primary = build_llm()
fallback = make_primary()
