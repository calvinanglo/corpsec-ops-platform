"""corpsec-ops-platform — DLP scanner daemon.

Watches mounted directories for new/modified files and runs DLP engine.
Integrates with reporter.py to emit alerts to Wazuh + TheHive.
"""
from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path

from dlp.engine import DLPEngine
from dlp.reporter import DLPReporter

logger = logging.getLogger(__name__)


class DLPScanner:
    """File system scanner — runs once or in daemon mode."""

    def __init__(self, watch_paths: list[Path], reporter: DLPReporter, engine: DLPEngine | None = None):
        self.watch_paths = watch_paths
        self.engine = engine or DLPEngine()
        self.reporter = reporter
        self._last_scan: dict[Path, float] = {}

    def scan_once(self) -> int:
        """Scan all watch paths once. Returns number of matches reported."""
        total_matches = 0
        for path in self.watch_paths:
            if not path.exists():
                logger.warning("Watch path does not exist: %s", path)
                continue
            if path.is_file():
                total_matches += self._scan_path(path)
            else:
                for f in path.rglob("*"):
                    if f.is_file():
                        total_matches += self._scan_path(f)
        return total_matches

    def watch(self, interval_seconds: int = 60) -> None:
        """Daemon mode — poll for changes every interval_seconds."""
        logger.info("Starting DLP scanner daemon — interval=%ds", interval_seconds)
        while True:
            try:
                count = self.scan_once()
                logger.info("Scan complete: %d matches", count)
            except Exception:
                logger.exception("Scan iteration failed")
            time.sleep(interval_seconds)

    def _scan_path(self, path: Path) -> int:
        """Scan a single file if changed since last check."""
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return 0
        if path in self._last_scan and self._last_scan[path] >= mtime:
            return 0
        self._last_scan[path] = mtime

        result = self.engine.scan_file(path)
        if result.matches:
            self.reporter.report(result)
        return len(result.matches)


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="corpsec-ops DLP scanner")
    parser.add_argument("--path", action="append", required=True, help="Path to watch (repeatable)")
    parser.add_argument("--policies", default="all", help="Comma-separated policy IDs or 'all'")
    parser.add_argument("--watch", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=60, help="Watch interval (seconds)")
    parser.add_argument("--output", default="/var/log/corpsec/dlp-alerts.jsonl", help="JSONL output for Wazuh")
    args = parser.parse_args()

    from dlp.policies import load_policies

    policy_ids = None if args.policies == "all" else args.policies.split(",")
    engine = DLPEngine(policies=load_policies(policy_ids))
    reporter = DLPReporter(jsonl_path=Path(args.output))
    scanner = DLPScanner(
        watch_paths=[Path(p) for p in args.path],
        reporter=reporter,
        engine=engine,
    )

    if args.watch:
        scanner.watch(args.interval)
    else:
        count = scanner.scan_once()
        logger.info("Scan complete — %d matches reported", count)


if __name__ == "__main__":
    main()
