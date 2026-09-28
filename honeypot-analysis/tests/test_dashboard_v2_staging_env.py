from __future__ import annotations

import importlib.util
import os
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "honeypot-analysis/deployment/dashboard-v2-staging/check-runtime-env.py"
spec = importlib.util.spec_from_file_location("staging_env_check", CHECKER)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_staging_env_requires_current_credentials_without_leaking_values() -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "staging.env"
        path.write_text("MONGODB_URI=\nPTI_ADMIN_PASSWORD=\nAUTH_SESSION_SECRET=\n")
        path.chmod(0o600)
        problems = module.check(path, expected_uid=os.getuid())
        assert {"MONGODB_URI", "PTI_ADMIN_PASSWORD", "AUTH_SESSION_SECRET"} <= {
            key for problem in problems for key in ("MONGODB_URI", "PTI_ADMIN_PASSWORD", "AUTH_SESSION_SECRET") if key in problem
        }
        path.write_text(
            "MONGODB_URI=mongodb+srv://example.invalid/db\n"
            "PTI_ADMIN_PASSWORD=long-synthetic-admin-password\n"
            "AUTH_SESSION_SECRET=synthetic-session-secret-with-32-plus-chars\n"
        )
        assert module.check(path, expected_uid=os.getuid()) == []
        path.write_text(path.read_text() + "PTI_ADMIN_PASSWORD=duplicate\n")
        assert any("repeats PTI_ADMIN_PASSWORD" in item for item in module.check(path, expected_uid=os.getuid()))
        path.chmod(0o644)
        assert module.check(path, expected_uid=os.getuid()) == [
            "staging environment ownership, type, or mode is unsafe"
        ]
