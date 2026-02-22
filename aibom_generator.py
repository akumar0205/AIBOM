#!/usr/bin/env python3
"""Backward-compatible entrypoint."""

from aibom.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
