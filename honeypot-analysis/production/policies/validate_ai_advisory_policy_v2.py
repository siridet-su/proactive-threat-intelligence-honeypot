"""Offline validator for the frozen Final-F AI advisory policy v2."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from production.ai_advisory.contracts_v2 import (
    DEFAULT_POLICY_PATH,
    contract_schema_sha256_v2,
    load_ai_advisory_policy_v2,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default=str(DEFAULT_POLICY_PATH))
    args = parser.parse_args()
    policy, policy_sha256, resolved = load_ai_advisory_policy_v2(
        Path(args.policy)
    )
    print(json.dumps({
        "schema_version": "ai_advisory_policy_validation.v2",
        "status": "PASS",
        "policy_path": resolved,
        "policy_sha256": policy_sha256,
        "provider_output_schema_sha256": contract_schema_sha256_v2(policy),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
