# IR-005: Account Compromise

| Severity | Owner | SLA |
|----------|-------|-----|
| HIGH | L2 SOC Lead | 1h |
| CRITICAL (privileged user) | L2 + Manager | 30min |

## Triggered By

- Wazuh Okta rules `100002` (brute force), `100003` (password spray), `100011` (MFA fatigue), `100020` (Tor login), `100021` (impossible travel)
- 1Password rules `100502` (brute force), `100503` (unusual country)
- GWS rules `100402` (brute force), `100403` (suspicious login flag from Google)
- User self-report ("I didn't do that login")

## Triage

1. Check Okta system log for the user — what's the timeline?
   - Multiple failed logins → brute force / password spray
   - Successful login from new geo → impossible travel
   - MFA approval not from user's device → MFA fatigue
   - OAuth grant to unfamiliar app → consent phishing
2. Whitelist exclusions:
   - User on documented business travel? Check HR system
   - VPN egress IP that geolocates incorrectly?
3. Determine if account is privileged (Okta admin, soc-lead role, etc.)

## Containment

Auto-remediation already runs for HIGH+ via `PB-ACCT-001`:
1. Disable user in Okta
2. Revoke all SSO sessions

Manually:
1. Revoke all OAuth tokens granted in last 24h:
   - Okta Admin → Users → <user> → Applications → revoke any unfamiliar grants
2. For Google Workspace: revoke OAuth scopes:
   ```
   GWS Admin Console → Security → API controls → Manage Third-Party App Access → revoke
   ```
3. For 1Password: rotate any vault items the user accessed in last 24h

## Investigation

1. Pull Okta system log for the user, last 7 days:
   - All sign-in events (success + failure)
   - All MFA factor changes
   - All OAuth grants
2. Check for persistence mechanisms:
   - Email forwarding rules (rule `100460` in GWS)
   - New OAuth app grants
   - New devices registered
   - Profile changes (recovery email modified?)
3. Map user activity during compromise window:
   - What data did they access?
   - What did they download?
   - What did they send via email?
4. Check CrowdStrike for endpoint activity at sign-in times

## Remediation

- **Confirmed compromise**:
  - Reset credentials
  - Re-enroll all MFA factors from a clean device
  - Audit and revert any persistence mechanisms (forwarding rules, OAuth grants)
  - 14-day heightened monitoring
  - User awareness conversation
- **Privileged account compromise**:
  - Add: rotate all secrets/keys the user had access to
  - Add: review all admin actions taken during compromise window
  - Add: incident report for compliance evidence (SOC 2 CC6.1 incident)

## ITIL Close

Document:
- Attack vector (brute force / phishing / token theft / MFA fatigue / etc.)
- Compromise window timestamps (first malicious sign-in to containment)
- Data exposure assessment
- Persistence mechanisms found and reverted
- Credentials reset / MFA re-enrolled — confirmation timestamps
- Lessons learned (e.g., user education, conditional access policy update)
