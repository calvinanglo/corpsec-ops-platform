"""corpsec-ops-platform — Flask API server for remediation actions.

Exposes endpoints called by Wazuh active-response scripts and n8n workflows:
  POST /remediate/disable-user      — Disable Okta user
  POST /remediate/revoke-session    — Revoke all SSO sessions
  POST /remediate/isolate-endpoint  — CrowdStrike RTR contain
  POST /remediate/block-domain      — DNS sinkhole
  POST /remediate/quarantine-file   — Move file to quarantine
  POST /remediate/execute           — Full playbook dispatcher
  POST /dlp/scan                    — Scan content for DLP
  POST /ai/detect                   — Analyze AI exfil indicators
  POST /compliance/collect          — Trigger evidence collection
  GET  /health                      — Liveness probe
"""
from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, request

from remediation.auto_remediate import AutoRemediate
from remediation.actions import disable_user, revoke_session, isolate_endpoint, block_domain, quarantine_file

logger = logging.getLogger(__name__)


def create_app() -> Flask:
    app = Flask(__name__)
    engine = AutoRemediate()

    @app.get("/health")
    def health():
        return jsonify(status="healthy", service="corpsec-python")

    # ── Direct action endpoints (called by Wazuh active-response) ──────────
    @app.post("/remediate/disable-user")
    def remediate_disable_user():
        body = request.get_json(force=True)
        synthetic_alert = {"data": {"user": body.get("user_email")}, "id": body.get("alert_id")}
        ok, details = disable_user.execute(synthetic_alert)
        return jsonify(success=ok, **details), (200 if ok else 500)

    @app.post("/remediate/revoke-session")
    def remediate_revoke_session():
        body = request.get_json(force=True)
        synthetic_alert = {"data": {"user": body.get("user_email")}, "id": body.get("alert_id")}
        ok, details = revoke_session.execute(synthetic_alert)
        return jsonify(success=ok, **details), (200 if ok else 500)

    @app.post("/remediate/isolate-endpoint")
    def remediate_isolate():
        body = request.get_json(force=True)
        synthetic_alert = {"data": {"device_id": body.get("device_id"), "hostname": body.get("hostname")}, "id": body.get("alert_id")}
        ok, details = isolate_endpoint.execute(synthetic_alert)
        return jsonify(success=ok, **details), (200 if ok else 500)

    @app.post("/remediate/block-domain")
    def remediate_block_domain():
        body = request.get_json(force=True)
        synthetic_alert = {
            "data": {
                "domain": body.get("domain"),
                "user": body.get("user"),
                "duration_seconds": body.get("duration_seconds", 3600),
            },
            "id": body.get("alert_id"),
        }
        ok, details = block_domain.execute(synthetic_alert)
        return jsonify(success=ok, **details), (200 if ok else 500)

    @app.post("/remediate/quarantine-file")
    def remediate_quarantine_file():
        body = request.get_json(force=True)
        synthetic_alert = {"data": {"file_path": body.get("file_path"), "user": body.get("user")}, "id": body.get("alert_id")}
        ok, details = quarantine_file.execute(synthetic_alert)
        return jsonify(success=ok, **details), (200 if ok else 500)

    # ── Full-playbook dispatcher (n8n calls this with a Wazuh alert) ───────
    @app.post("/remediate/execute")
    def remediate_execute():
        alert = request.get_json(force=True)
        result = engine.receive_alert(alert)
        return jsonify(result.as_dict()), 200

    # ── DLP scan endpoint ─────────────────────────────────────────────────
    @app.post("/dlp/scan")
    def dlp_scan():
        body = request.get_json(force=True)
        from dlp.engine import DLPEngine
        e = DLPEngine()
        if "text" in body:
            matches = e.scan_text(body["text"], body.get("context", {}))
            return jsonify(matches=[m.as_dict() for m in matches])
        if "file_path" in body:
            result = e.scan_file(body["file_path"])
            return jsonify(result.as_dict())
        return jsonify(error="provide text or file_path"), 400

    # ── AI detection endpoint ─────────────────────────────────────────────
    @app.post("/ai/detect")
    def ai_detect():
        body = request.get_json(force=True)
        from ai_detection.detector import AIExfilDetector
        d = AIExfilDetector()
        user = body.get("user", "unknown")
        if "host" in body:
            alert = d.analyze_dns_query(user, body["host"])
        elif "url" in body:
            alert = d.analyze_proxy_log(user, body["url"], body.get("method", "POST"), int(body.get("upload_bytes", 0)))
        else:
            return jsonify(error="provide host or url"), 400
        if alert:
            d.emit(alert)
            return jsonify(alert=alert.as_dict())
        return jsonify(alert=None)

    # ── Compliance evidence trigger ───────────────────────────────────────
    @app.post("/compliance/collect")
    def compliance_collect():
        body = request.get_json(force=True)
        framework = body.get("framework", "all")
        from compliance.evidence_collector import EvidenceCollector
        collector = EvidenceCollector()
        results = collector.collect_all(framework)
        return jsonify(framework=framework, packages=[r.as_dict() for r in results])

    return app


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
