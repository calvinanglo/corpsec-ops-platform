# COMP-002: ISO 27001 Audit Evidence

| Frequency | Owner |
|-----------|-------|
| Daily (automated) | n8n + corpsec-python |
| Quarterly review | Compliance Admin + ISMS Lead |
| Pre-certification audit | Full team |

## Goal

Maintain audit-ready evidence aligned with ISO 27001:2022 Annex A controls
mapped in `compliance/control-mapping/iso27001-controls.yml`.

## Same automation as COMP-001

The same n8n workflow collects ISO 27001 + SOC 2 evidence in one pass.
Evidence stored at: `compliance/evidence/iso27001/{control_id}/{date}/`

## Quarterly Review Tasks

1. Review Annex A control coverage:
   - All 14 controls implemented in this platform should have <30-day-old evidence
   - Controls without automation (e.g., A.5.1 policies) need manual update

2. Update Statement of Applicability (SoA):
   - For each Annex A control: applicable / not applicable / implementation status
   - Document any compensating controls

3. Internal audit walk-through:
   - Pick 5 random controls
   - Verify evidence collected matches the control statement
   - Document gaps in `compliance/evidence/iso27001/_internal-audits/`

## Risk Treatment Plan Linkage

For each ISO control, the risk register must show:
- The risk being addressed
- The control treatment chosen
- The evidence that the treatment is operating

`compliance/templates/risk-register-template.md` provides the format.

## Pre-Certification Audit (Stage 1 + Stage 2)

### Stage 1 (Documentation review)
1. Provide auditor with:
   - ISMS scope statement
   - Statement of Applicability
   - Risk treatment plan
   - All policies (`docs/policies/`)
   - This platform's architecture doc (`docs/00-architecture.md`)

### Stage 2 (Implementation evidence)
1. Generate full evidence package:
   ```bash
   make evidence-collect
   tar -czvf iso27001-audit-$(date +%Y%m%d).tar.gz compliance/evidence/iso27001/
   ```
2. Walk through each control with auditor using mapping:
   - `compliance/control-mapping/iso27001-controls.yml`
3. Demonstrate live (auditor screen-sharing):
   - Wazuh dashboard for log review (A.12.4)
   - Okta admin for access control (A.9.1)
   - TheHive for IR (A.16.1)
   - Vulnerability detector results (A.12.6)

## Common Findings to Pre-Empt

- **A.12.4 — Logging**: ensure log retention >= 90 days (Loki retention config)
- **A.12.6 — Vulnerability mgmt**: ensure scan cadence ≤ 7 days (Wazuh interval)
- **A.16.1 — IR**: ensure runbooks are dated and reviewed quarterly
- **A.18.1 — Compliance**: keep evidence freshness ≤ 30 days
