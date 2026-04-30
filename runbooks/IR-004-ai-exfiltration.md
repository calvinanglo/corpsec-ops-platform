# IR-004: AI Exfiltration Response

| Severity | Owner | SLA |
|----------|-------|-----|
| MEDIUM | L1 SOC Analyst | 4h |
| HIGH | L2 SOC Lead | 1h |
| CRITICAL (large upload + client data + unauthorized service) | L2 + Manager + Legal | 30min |

## Triggered By

- Wazuh AI exfil rules `100200-100299` (custom AI detection engine output)
- Specifically: `100201` (proxy upload), `100202` (CRITICAL >1MB upload), `100203` (correlated multi-vector)

## Triage

1. Open the auto-created case in TheHive
2. Verify the AI service classification:
   ```
   ai_service_classification:
     AUTHORIZED_CORPORATE → close as benign
     UNAUTHORIZED_PERSONAL → continue triage
     UNKNOWN → manual classification, then update python/ai_detection/policies.py registry
   ```
3. Quantify the upload (from proxy log analyzer fields):
   - `upload_bytes`: actual content sent
   - `<10KB` → likely just a prompt, not data exfil
   - `10KB-1MB` → moderate content (paragraph, short doc)
   - `>1MB` → bulk content (full document, dataset)

4. Identify the user:
   - Map proxy `src_ip` to user via Okta active sessions
   - Cross-check with Okta sign-in logs at the same timestamp

## Containment

For CRITICAL (rule `100202` or `100203`) auto-remediation already runs (`PB-AI-001`):
1. Domain blocked at DNS sinkhole
2. User SSO sessions revoked

For HIGH/MEDIUM, decide manually:
- Block the AI service domain corp-wide?
- Revoke just this user's session?
- Educational reminder only?

## Investigation

1. Pull all proxy logs for the user in the last 24h:
   ```
   src_ip:<user_ip> OR data.user:<user_email>
   ```
2. Identify what data was uploaded:
   - DLP engine should have caught content if it traversed monitored paths
   - If clipboard-based: limited visibility (no real-time clipboard logging in this stack)
3. Check Google Drive for recent file access by user (could indicate what they had open before pasting)
4. Check 1Password audit for credential access patterns at same timestamp

## Critical: Client Data Assessment

For Clio specifically (legal tech context):
- If uploaded data contained client matter IDs, attorney-client privilege markers, or trust account info:
  - **Immediate legal hold**
  - **Assess client notification obligation** per applicable bar association rules
  - **Document everything** — chain of custody for potential legal proceeding

## Remediation

- **Confirmed unauthorized exfil**:
  - User policy violation → manager notification, training
  - Update AI service registry if this discovered a new unauthorized service
  - Consider sanctioning the corporate AI tool to reduce shadow-AI demand
- **Authorized AI used incorrectly** (e.g., correctly used the corporate ChatGPT Enterprise tenant but submitted prohibited data):
  - User education on what data is permitted in AI tools
  - Update AI usage policy if the rules are unclear
- **False positive** (not actually data, just metadata/headers):
  - Tune `python/ai_detection/detector.py` thresholds
  - Add to `policies.py` exclusion patterns

## ITIL Close

Document:
- AI service used + classification (corporate / personal / unknown)
- Data classification (general corp / PII / legal-privileged / financial)
- Estimated volume (bytes uploaded)
- Whether client data involved
- Whether legal/regulatory notification triggered
- Remediation action taken
- Policy enforcement applied
