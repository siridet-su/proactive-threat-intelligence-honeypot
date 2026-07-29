"""Scheduled, bounded refresh entry point for external intelligence feeds."""

from __future__ import annotations

import argparse
import json
from typing import List, Optional

from production.enrichment.feed_status import (
    collect_feed_status,
    write_runtime_feed_provenance,
)
from production.enrichment.mitre_attack_loader import load_mitre_attack_db
from production.enrichment.threat_feed_loader import load_cisa_kev, load_sigma_rules
from production.utils.config import ProductionConfig
from production.utils.sensitive_data import redact_exception_for_log


def refresh_feeds(config: ProductionConfig, *, check_only: bool = False) -> dict:
    if not config.enable_feed_loading:
        result = {
            "status": "disabled",
            "loading_enabled": False,
            "feeds": collect_feed_status(config),
        }
        try:
            result["runtime_feed_provenance"] = write_runtime_feed_provenance(
                config, result["feeds"]
            )
        except Exception as exc:
            result["status"] = "provenance_unavailable"
            result["runtime_feed_provenance"] = {
                "recorded": False,
                "error": redact_exception_for_log(exc),
            }
        return result
    if not check_only:
        load_cisa_kev(
            force_refresh=True,
            cache_path=config.cisa_cache_path or None,
        )
        load_sigma_rules(
            force_refresh=True,
            cache_path=config.sigma_cache_path or None,
        )
        load_mitre_attack_db(
            cache_path=config.mitre_attack_path or None,
            force_refresh=True,
            silent=True,
        )
    feeds = collect_feed_status(config)
    states = [feeds[name]["status"] for name in ("cisa", "sigma", "mitre")]
    usable = sum(state in {"fresh", "stale"} for state in states)
    result = {
        "status": "complete" if usable == 3 else "partial" if usable else "unavailable",
        "loading_enabled": True,
        "feeds": feeds,
    }
    try:
        result["runtime_feed_provenance"] = write_runtime_feed_provenance(
            config, feeds
        )
    except Exception as exc:
        result["status"] = "provenance_unavailable"
        result["runtime_feed_provenance"] = {
            "recorded": False,
            "error": redact_exception_for_log(exc),
        }
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Refresh external intelligence feeds.")
    parser.add_argument("--config", help="Path to production JSON config.")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Report current cache state without contacting providers.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    result = refresh_feeds(
        ProductionConfig.from_env(args.config),
        check_only=args.check_only,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"complete", "disabled"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
