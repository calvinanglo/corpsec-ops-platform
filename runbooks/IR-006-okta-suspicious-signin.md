# IR-006: Okta Suspicious Sign-In

| Severity | Owner | SLA |
|----------|-------|-----|
| MEDIUM (single anomaly) | L1 SOC Analyst | 4h |
| HIGH (multiple risk factors) | L2 SOC Lead | 1h |

## Triggered By

- Wazuh Okta rules `100020` (Tor/proxy login), `100021` (impossible travel), `100040` (new API token), `100061` (security policy disabled)
- Okta ThreatInsight detection (high-risk sign-in)

## Triage

1. Open the case in TheHive
2. Pull the user's recent sign-in pattern:
   ```
   In Wazuh dashboard:
     data.actor.alternateId:"<user>" AND rule.groups:okta
   ```
3. Map the geographic distance / time:
   - Vancouver → Frankfurt in 30 minutes = impossible
   - Vancouver → Seattle in 2 hours = plausible (driving)
4. Check user's documented travel:
   - Does HR have a travel notification?
   - Does Slack profile show "out of office"?

## Containment

For HIGH severity:
1. **Disable user pending verification**:
   ```bash
   curl -X POST http://corpsec-python:8080/remediate/disable-user \
     -d '{"user_email":"<user>","alert_id":"<case_id>"}'
   ```
2. **Revoke active sessions**:
   ```bash
   curl -X POST http://corpsec-python:8080/remediate/revoke-session \
     -d '{"user_email":"<user>","alert_id":"<case_id>"}'
   ```
3. **Contact user via verified channel** (NOT email — could be compromised):
   - Phone call
   - Slack DM with verification question
   - In-person if local

## Investigation

1. Apply IR-005 investigation steps if user confirms compromise
2. If user verifies they did the login (e.g., new VPN endpoint):
   - Add the IP to known-good list in Okta network zones
   - Update detection thresholds if too noisy

## Remediation

- **User verified login was theirs**:
  - Re-enable account
  - Update Okta network zones with the new known-good IP
  - Document for tuning
- **Compromise confirmed**:
  - Follow IR-005 (Account Compromise) full procedure

## ITIL Close

- Outcome: `verified_user` | `compromise_confirmed` | `inconclusive`
- Risk indicators present (Tor, impossible travel, new device, etc.)
- Tuning applied if false positive
