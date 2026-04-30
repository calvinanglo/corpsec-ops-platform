# IR-007: CrowdStrike Falcon Detection

| Severity | Owner | SLA |
|----------|-------|-----|
| MEDIUM (Falcon "Low") | L1 SOC Analyst | 4h |
| HIGH (Falcon "Medium-High") | L2 SOC Lead | 1h |
| CRITICAL (Falcon "Critical") | L2 + Manager | 30min |

## Triggered By

- CrowdStrike Falcon detection forwarded by `integrations/crowdstrike/detection_streamer.py`
- Wazuh CrowdStrike rules `100300-100399` (severity-mapped)
- Direct alert in Falcon console (escalated by sensor)

## Triage

1. Open Falcon console:
   - Console URL: `https://falcon.crowdstrike.com`
   - Detections → filter by detection ID from the case
2. Examine process tree:
   - What spawned this process?
   - What did it spawn?
   - What network connections did it make?
3. Map to MITRE ATT&CK tactic/technique
4. Check IOC reputation:
   - VirusTotal (file hash via Cortex analyzer)
   - Hybrid Analysis
   - AbuseIPDB (network destination)

## Containment

For HIGH+, auto-remediation runs `PB-EDR-001`:
1. Endpoint network-isolated via Falcon RTR
2. TheHive case created

Manual additional steps:
1. **For confirmed lateral movement**:
   - Search the file hash across the entire fleet (Falcon → IOC search)
   - Add hash to Falcon custom IOC blocklist
2. **For credential dumping** (Mimikatz, LSASS dumping):
   - Disable affected user(s) in Okta immediately
   - Reset all credentials of users who logged into the host in last 7 days
3. **For ransomware indicators**:
   - Notify backup team to verify recent restore points
   - Disable any user account that has admin on the host

## Investigation

1. Falcon RTR session (read-only): inspect file system, registry, processes
   - `ls /Users/.../Downloads`
   - `cat /var/log/auth.log` (Linux)
   - `Get-Process` (Windows)
2. Pull host events from Wazuh: search by agent name
3. Check pivot points:
   - Username under which malicious process ran
   - All processes spawned by that user in last 24h
   - All network connections from that host
4. Document attack chain in TheHive case as observable graph

## Remediation

- **Confirmed compromise**:
  - Reimage endpoint (after forensic snapshot via Ansible playbook)
  - Re-enroll Falcon sensor + Wazuh agent + Intune device
- **False positive**:
  - Submit Falcon IOA exception with justification
  - Document tuning in case
- **Lateral movement found**:
  - Containment expanded to all affected hosts
  - Full network segmentation review

## ITIL Close

- MITRE technique(s) confirmed
- Detection true/false positive
- Number of affected endpoints
- Total response time (detection → containment)
- Lessons learned (CrowdStrike policy tuning, new Wazuh custom rule needed?)
