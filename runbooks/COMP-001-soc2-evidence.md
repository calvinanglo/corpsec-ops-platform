# COMP-001: SOC 2 Evidence Collection

| Frequency | Owner |
|-----------|-------|
| Daily (automated) | n8n + corpsec-python |
| Weekly summary | Compliance Admin |
| Pre-audit (full) | Compliance Admin + SOC Lead |

## Goal

Maintain audit-ready evidence for all SOC 2 Trust Services Criteria controls
mapped in `compliance/control-mapping/soc2-controls.yml`.

## Daily Automated Collection (no manual action)

n8n workflow `compliance-evidence` runs at 02:00 daily:
1. Calls `POST /compliance/collect` on corpsec-python
2. Each control queries the right source (Okta API, CrowdStrike, Wazuh, etc.)
3. Evidence written to `compliance/evidence/{framework}/{control_id}/{date}/`
4. SHA-256 hash computed for integrity

## Weekly Manual Review

Every Monday morning:

1. Check evidence freshness:
   ```bash
   make evidence-collect      # if any are stale, this populates them
   ls -la compliance/evidence/soc2/*/  # verify all controls have today's date
   ```

2. Review evidence summary in Grafana:
   - Open `Compliance Posture` dashboard
   - Check each control's pass/fail status
   - Investigate any FAIL or stale (>7d) status

3. Update `runbooks/COMP-001-soc2-evidence.md` log section below

## Pre-Audit Collection (annual)

1. Run full collection 30 days before audit:
   ```bash
   make evidence-collect
   ```

2. Generate audit package:
   ```bash
   tar -czvf audit-package-$(date +%Y%m%d).tar.gz compliance/evidence/
   sha256sum audit-package-*.tar.gz > audit-package.sha256
   ```

3. Verify integrity:
   ```bash
   sha256sum -c audit-package.sha256
   ```

4. Walk through each control with audit team — `compliance/control-mapping/soc2-controls.yml`
   maps every control to its evidence source for traceability.

## Common Audit Questions and Where to Find Evidence

| Auditor question | Evidence location |
|------------------|-------------------|
| "How do you control privileged access?" | `evidence/soc2/CC6.1/` (Okta role exports) |
| "Show MFA enforcement" | `evidence/soc2/CC6.2/` (Okta MFA policy export) |
| "Show vulnerability scanning cadence" | `evidence/soc2/CC6.3/` (Wazuh syscollector results) |
| "How do you detect malware?" | `evidence/soc2/CC6.8/` (CrowdStrike EDR coverage) |
| "Show your IR process" | `runbooks/IR-001` through `IR-008` + `evidence/soc2/CC7.4/` (TheHive metrics) |
| "How do you manage change?" | `evidence/soc2/CC8.1/` (git commit log) |

## Audit Trail

When manual evidence collection or override is performed, log it here:

| Date | Operator | Action | Justification |
|------|----------|--------|---------------|
| YYYY-MM-DD | <name> | <action> | <reason> |
