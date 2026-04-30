# IR-008: Google Workspace Alert Triage

| Severity | Owner | SLA |
|----------|-------|-----|
| MEDIUM | L1 SOC Analyst | 4h |
| HIGH | L2 SOC Lead | 1h |

## Triggered By

- GWS Alert Center (Google's native alert system) — pulled by `integrations/google_workspace/alert_center_poller.py`
- Wazuh GWS rules `100400-100499`
- Specifically: `100431` (drive made public), `100432` (bulk download), `100440` (DLP triggered), `100460` (external email forwarding)

## Triage by Alert Type

### Drive doc made PUBLIC (rule `100431`)
1. Open Drive in GWS Admin: Reports → Drive
2. Find the document by ID/title
3. Check who accessed it externally before/after sharing change
4. Determine if intentional (e.g., public marketing PDF) or accidental

### Bulk download (rule `100432`)
1. Pull download log for user in last 24h
2. Compare to baseline (typical user downloads <10/day)
3. Check user's recent activity (preparing to leave? Project handoff? Audit prep?)

### External email forwarding (rule `100460`)
1. CRITICAL by default — this is a classic BEC persistence mechanism
2. Open Gmail settings for the user (admin can impersonate)
3. Identify destination — internal personal address vs unknown external
4. Check when rule was created vs user's last legitimate sign-in

## Containment

For all CRITICAL:
- Disable user pending review (Okta API call)
- Revoke OAuth grants
- For email forwarding: remove the rule

```bash
# Quick containment via Okta
curl -X POST http://corpsec-python:8080/remediate/disable-user \
  -d '{"user_email":"<user>","alert_id":"<case_id>"}'
```

## Investigation

1. Pull all GWS audit events for user in last 7 days
2. Cross-reference with Okta sign-in logs
3. For drive sharing: identify external domains that received share notifications
4. For bulk downloads: identify what files (DLP scan retroactively if needed)

## Remediation

- **Accidental sharing**: Revert sharing settings, user education
- **Compromised account doing the sharing**: Follow IR-005 full procedure
- **Insider threat exfiltration**: HR + Legal involvement, evidence preservation

## ITIL Close

- Alert type
- Volume (# of files / size)
- External destinations identified
- Compromise vs insider determination
- Remediation outcome
