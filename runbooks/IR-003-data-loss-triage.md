# IR-003: Data Loss Triage (DLP)

| Severity | Owner | SLA |
|----------|-------|-----|
| MEDIUM | L1 SOC Analyst | 4h |
| HIGH | L2 SOC Lead | 1h |
| CRITICAL (legal/client data) | L2 + Manager + Legal | 30min |

## Triggered By

- Wazuh DLP rules `100100-100199` (custom DLP engine output)
- Google Workspace DLP policy violations (rule `100440`)
- 1Password vault export (rule `100512`)
- FIM rule `100740` (sensitive file deletion)

## Triage — Signal-vs-Noise Checklist

This is the **key SOC analyst skill** — most DLP alerts are false positives.
Apply this checklist before any containment action:

| # | Question | If "No" → |
|---|----------|-----------|
| 1 | Is the matched data **actually sensitive**? Open the file and verify. | Likely false positive — tune policy |
| 2 | Confidence score >= 0.7? | Review context window for noise |
| 3 | Is the **destination unauthorized** (external email, personal cloud, AI)? | Lower severity — likely intra-team share |
| 4 | Is the user **authorized for this data classification**? Check Okta group membership. | Reduce severity — known legitimate access |
| 5 | Is the **volume unusual** (single doc vs bulk)? | Lower severity for one-off |
| 6 | **Time of day**: business hours vs after-hours? | After-hours +1 severity |
| 7 | Is this a **first occurrence** for this user, or repeat behavior? | Repeat → escalate |
| 8 | **HR context**: did the user recently give notice? | If yes → escalate to HR/Legal |

## Containment

### If signals confirm true positive:

1. **Quarantine the file** (still in transit):
   ```bash
   curl -X POST http://corpsec-python:8080/remediate/quarantine-file \
     -H "Content-Type: application/json" \
     -d '{"file_path":"<path>","user":"<email>","alert_id":"<case_id>"}'
   ```

2. **Block destination** if external:
   ```bash
   curl -X POST http://corpsec-python:8080/remediate/block-domain \
     -d '{"domain":"<destination>","duration_seconds":3600}'
   ```

3. **For HIGH+ involving client/legal data** (Clio context — attorney-client privilege):
   - Disable user pending review (auto-triggered by `PB-DLP-001`)
   - Notify Legal and Compliance immediately
   - Preserve evidence chain — do NOT alter the file post-quarantine

## Investigation

1. Review full DLP alert details in TheHive case
2. Pull related Wazuh events for the user in last 24h:
   ```
   data.user:"<user>" AND rule.groups:dlp
   ```
3. Check 1Password audit log for vault access patterns
4. Check CrowdStrike for unusual process activity at the time of alert
5. Determine intent:
   - **Accidental** (user attached wrong file, unaware of policy)
   - **Intentional** (deliberate exfiltration — possibly preceding voluntary departure)

## Remediation

- **Intentional exfiltration confirmed**:
  - Escalate to HR + Legal
  - Preserve evidence (file copy, audit trail, all related events)
  - Coordinate with HR on access removal timeline
- **Accidental**:
  - User education conversation
  - Reminder of DLP policy
  - Document in case for trend analysis (recurring accidents = process gap)
- **False positive**:
  - Update `python/dlp/policies.py` `false_positive_patterns` for the matching policy
  - Re-run scan to verify suppression
  - Document tuning in case

## ITIL Close

- Classification: `confirmed_loss` | `attempted_loss` | `false_positive`
- Data classification: PII / Financial / Legal-Privileged / Code Secrets
- Volume: # of records / file size
- Destination: internal / external / unknown
- Remediation actions taken
- Tuning applied (if false positive)
