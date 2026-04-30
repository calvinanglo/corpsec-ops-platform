"""1Password CLI wrapper.

Uses the `op` CLI binary with a Service Account token (OP_SERVICE_ACCOUNT_TOKEN
env var). Supports secret retrieval and audit event polling.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


class OnePasswordCLI:
    """Wraps the `op` CLI tool. Service account token must be in env."""

    def __init__(self):
        if not os.getenv("OP_SERVICE_ACCOUNT_TOKEN"):
            raise RuntimeError("OP_SERVICE_ACCOUNT_TOKEN must be set")

    def get_secret(self, vault: str, item: str, field: str = "password") -> str:
        """Retrieve a single field from a vault item."""
        cmd = ["op", "read", f"op://{vault}/{item}/{field}"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()

    def list_vaults(self) -> list[dict]:
        cmd = ["op", "vault", "list", "--format=json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def list_items(self, vault: str) -> list[dict]:
        cmd = ["op", "item", "list", f"--vault={vault}", "--format=json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)

    def list_users(self) -> list[dict]:
        cmd = ["op", "user", "list", "--format=json"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
