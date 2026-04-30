"""CrowdStrike Real-Time Response (RTR) command runner.

Wraps Falcon RTR for safe, audit-logged command execution against contained hosts.
Used by L2 SOC analysts during active investigations.

ALL commands logged to audit JSONL — RTR is highly privileged.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from integrations.crowdstrike.falcon_client import FalconClient

logger = logging.getLogger(__name__)
AUDIT_LOG = Path(os.getenv("AUDIT_LOG_PATH", "/var/log/corpsec/audit.jsonl"))

# Whitelist of safe RTR commands (read-only by default)
SAFE_COMMANDS = {"ls", "cat", "ps", "netstat", "ipconfig", "users", "history", "filehash", "pwd", "cd", "env", "reg query"}
DANGEROUS_COMMANDS = {"rm", "kill", "shutdown", "reg delete", "put", "runscript", "xmemdump"}


def _audit(action: str, device_id: str, command: str, result: dict) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "crowdstrike-rtr",
        "action": action,
        "device_id": device_id,
        "command": command,
        "result": result,
        "operator": os.getenv("USER", "unknown"),
    }
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def init_session(device_id: str) -> str:
    """Open an RTR session against a host. Returns session_id."""
    client = FalconClient()
    response = client._rtr.init_session(device_id=device_id)
    body = response.get("body", {})
    if response.get("status_code") != 201:
        raise RuntimeError(f"RTR session init failed: {body}")
    session_id = body["resources"][0]["session_id"]
    _audit("session_init", device_id, "", {"session_id": session_id})
    logger.info("RTR session opened for %s — id=%s", device_id, session_id)
    return session_id


def execute_command(session_id: str, command: str, device_id: str = "", allow_dangerous: bool = False) -> dict:
    """Execute an RTR command. Refuses dangerous commands unless explicitly allowed."""
    base = command.split()[0].lower() if command else ""
    if base in DANGEROUS_COMMANDS and not allow_dangerous:
        msg = f"Refused dangerous command '{command}' — pass allow_dangerous=True if intentional"
        _audit("execute_refused", device_id, command, {"error": msg})
        raise RuntimeError(msg)

    client = FalconClient()
    body_data = {"base_command": base, "command_string": command, "session_id": session_id}
    response = client._rtr.execute_active_responder_command(body=body_data)
    result = response.get("body", {})
    _audit("execute", device_id, command, result)
    return result


def end_session(session_id: str, device_id: str = "") -> dict:
    client = FalconClient()
    response = client._rtr.delete_session(session_id=session_id)
    result = response.get("body", {})
    _audit("session_end", device_id, "", {"session_id": session_id})
    return result


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="CrowdStrike RTR command runner")
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--command", required=True, help="RTR command to run")
    parser.add_argument("--allow-dangerous", action="store_true", help="Override dangerous-command guard")
    args = parser.parse_args()

    session_id = init_session(args.device_id)
    try:
        result = execute_command(session_id, args.command, args.device_id, args.allow_dangerous)
        print(json.dumps(result, indent=2))
    finally:
        end_session(session_id, args.device_id)


if __name__ == "__main__":
    main()
