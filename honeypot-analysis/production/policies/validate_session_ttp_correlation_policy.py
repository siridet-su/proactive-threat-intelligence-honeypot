"""CLI wrapper for validating session-level TTP correlation policy files."""

from __future__ import annotations

from production.correlation.session_ttp_correlation import main


if __name__ == "__main__":
    raise SystemExit(main())
