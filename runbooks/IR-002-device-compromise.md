# IR-002: Device Compromise (EDR Detection)

| Severity | Owner | SLA |
|----------|-------|-----|
| HIGH (malware confirmed) | L2 SOC Lead | 1h |
| CRITICAL (ransomware/active breach) | L2 + Manager | 30min |

## Triggered By

- CrowdStrike Falcon detection (severity High/Critical)
- Wazuh EDR rules (`100300-100399`, especially `100320-100322` for ransomware/Mimikatz)
- FIM rule `100740` — sensitive file deleted
- User reports (slow performance, ransom note, unexpected pop-ups)

## Triage

1. Open the auto-created TheHive case
2. Verify the alert is not a known-good (e.g., security team running Mimikatz for testing)
3. Run Cortex analyzers:
   - VirusTotal (file hash)
   - WazuhAnalyzer (other detections on this agent in last 24h)
4. Check CrowdStrike → Detections → Process Tree to see what spawned the suspicious process
5. Determine severity:
   - Single artifact, no lateral movement signals → HIGH
   - Multiple endpoints with same hash → CRITICAL (campaign in progress)
   - Ransomware indicators (vssadmin delete, encryption activity) → CRITICAL

## Containment

1. **Isolate the endpoint immediately** (CrowdStrike RTR network containment):
   ```bash
   curl -X POST http://corpsec-python:8080/remediate/isolate-endpoint \
     -H "Content-Type: application/json" \
     -d '{"device_id":"<falcon_device_id>","alert_id":"<case_id>"}'
   ```
2. **Capture forensic snapshot** before reimaging:
   ```bash
   ansible-playbook ansible/playbooks/incident-contain.yml \
     -e "target_host=<hostname> confirm=YES"
   ```
3. **For ransomware specifically**:
   - Disable the user's Okta account to prevent credential abuse
   - Block C2 domains via DNS sinkhole (corpsec-python `/remediate/block-domain`)

## Investigation

1. CrowdStrike → Detections → Open detection → review:
   - Process tree (what spawned the malicious process)
   - Network connections (where was it calling?)
   - File modifications (what did it touch?)
2. Wazuh dashboard → search FIM events for the agent in the last 24h
3. Check for lateral movement:
   - Search CrowdStrike IOC across fleet for the file hash
   - Check Okta system log for the affected user's sign-ins from new endpoints
4. Identify infection vector (phishing email with attachment? Drive-by? USB? Lateral?)

## Remediation

- **Confirmed malware**:
  - Reimage endpoint from clean image
  - Re-enroll in CrowdStrike + Wazuh + Intune
  - User receives clean replacement / restored device
  - User credentials reset in Okta with re-MFA enrollment
- **Lateral movement confirmed**:
  - Apply CrowdStrike IOC across fleet to block file hash globally
  - Add Wazuh custom rule for the IOC if pattern is novel
  - Hunt for other affected hosts before lifting containment
- **False positive**:
  - Document in CrowdStrike custom IOA exclusion (with justification + sign-off)
  - Add to Wazuh tuning exclusion list

## ITIL Close

- Document: malware family, infection vector, # of affected endpoints, lateral movement assessment
- Update IR playbook with any new TTPs observed
- Schedule lessons-learned review if HIGH+ severity
- File aggregate metrics for monthly SOC report
