# IR-001: Phishing Response

| Severity | Owner | SLA |
|----------|-------|-----|
| MEDIUM (single user) | L1 SOC Analyst | 4h |
| HIGH (multiple users / executive target) | L2 SOC Lead | 1h |

## Triggered By

- User report via Phish Alert button (forwards to `phishing-report@corpsec.local`, n8n workflow `phishing-report-triage` creates case)
- Wazuh GWS rule `100401`+ (login failures correlated with phishing-related sender domain)
- GoPhish campaign post-mortem identifies organic clicks beyond simulation

## Triage

1. Open the TheHive case auto-created by n8n
2. Run Cortex analyzers on the suspicious URL/sender:
   - VirusTotal (URL + domain reputation)
   - AbuseIPDB (sender IP)
   - WazuhAnalyzer (related Wazuh alerts for the sender domain across all agents)
3. Determine scope:
   ```bash
   # In Wazuh dashboard, search for the sender domain across all GWS audit logs
   data.actor.email:"<sender>" OR full_log:"<domain>"
   ```
   - Single user → MEDIUM (targeted spear-phish)
   - Multiple users → HIGH (bulk campaign)
   - Executive recipient → HIGH (whaling/BEC indicator)

## Containment

1. **Block the sender** at the email gateway:
   - Google Workspace Admin → Security → Email allowlist/blocklist → add sender domain to blocklist
2. **For users who submitted credentials** (via campaign URL or replied with secrets):
   ```bash
   # Disable the user pending password reset
   curl -X POST http://corpsec-python:8080/remediate/disable-user \
     -H "Content-Type: application/json" \
     -d '{"user_email":"<user>","alert_id":"<case_id>"}'
   ```
   - Force password reset in Okta: Admin Console → Users → <user> → More Actions → Reset Password
   - Revoke all active sessions: same screen → "Clear User Sessions"
   - Revoke OAuth tokens granted in last 24h
3. **For users who opened attachments**:
   - CrowdStrike Console → Hosts → search by username → contain endpoint
   - Trigger forensic snapshot via Ansible: `ansible-playbook playbooks/incident-contain.yml -e "target_host=<hostname> confirm=YES"`

## Investigation

1. Extract email headers from the user-reported sample
2. Search Wazuh for the sender domain across **all** sources (Okta, GWS, CrowdStrike, proxy)
3. Check proxy logs for clicks on the phishing URL
4. Check CrowdStrike for execution artifacts on endpoints that opened attachments
5. Check Okta sign-in logs for activity from new IPs/devices for affected users

## Remediation

- **Confirmed credential compromise**: 
  - Full account audit (recent logins, OAuth grants, mailbox forwarding rules, group changes)
  - Re-enroll user in MFA from a clean device
  - 24h heightened monitoring (search for the user in Wazuh/CrowdStrike daily)
- **Confirmed malware execution**: 
  - Reimage endpoint
  - Check for lateral movement (same hash on other hosts via CrowdStrike IOC search)
  - Update Wazuh rules with new IOCs
- **False positive**: 
  - Document IOC in case for tuning
  - Add to GoPhish campaign awareness debrief

## ITIL Close

In TheHive case:
- Set status to **Resolved**
- Document: IOCs, affected user count, containment actions taken, time-to-containment
- Tag case with: `phishing`, `lessons-learned-{quarter}`
- If credential compromise confirmed, also create child case for HR/legal notification per company policy
