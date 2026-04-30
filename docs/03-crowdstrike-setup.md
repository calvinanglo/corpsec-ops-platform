# CrowdStrike Falcon Setup Guide

## Sign-Up

1. https://www.crowdstrike.com/products/free-trial/
2. Submit form, wait for approval (~24h)
3. You will receive: customer ID (CID), Falcon console URL, sensor download link

## Install Sensor

### Windows
```powershell
WindowsSensor.exe /install /quiet /norestart CID=<your_cid>
```

### Linux (Ubuntu/Debian)
```bash
sudo dpkg -i falcon-sensor_*.deb
sudo /opt/CrowdStrike/falconctl -s --cid=<your_cid>
sudo systemctl start falcon-sensor
```

### macOS
Run installer pkg, then `sudo /Applications/Falcon.app/Contents/Resources/falconctl license <CID>`

## Generate API Credentials

1. Falcon Console → Support → API Clients and Keys → Create API Client
2. Name: `corpsec-ops-platform`
3. Scopes (read-only is sufficient for this portfolio):
   - Detections: Read
   - Hosts: Read, Write (for containment)
   - Real Time Response: Read, Write (for RTR)
   - Spotlight: Read (for vuln data)
4. Save Client ID + Client Secret

## Configure .env

```
CROWDSTRIKE_CLIENT_ID=<id>
CROWDSTRIKE_CLIENT_SECRET=<secret>
CROWDSTRIKE_BASE_URL=https://api.crowdstrike.com    # or api.us-2, api.eu-1, etc.
```

## Trigger Test Detection

EICAR test file (safe — antivirus standard test):

### Windows
```powershell
Set-Content -Path "$env:USERPROFILE\Desktop\eicar.txt" `
  -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
```

### Linux/macOS
```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
```

Within 5 minutes, you'll see a Detection in the Falcon console.

## Verify

```bash
make sync-crowdstrike
# Should pull the eicar detection to /var/log/corpsec/crowdstrike-detections.jsonl
```

Check Wazuh dashboard — the eicar event should appear as a Wazuh alert (rule 100302).

## Required Screenshots

- [ ] `01-falcon-dashboard.png` — Falcon dashboard home
- [ ] `02-detections.png` — Detections list with the eicar detection
- [ ] `03-host-management.png` — Host inventory with your enrolled endpoint
- [ ] `04-mitre-coverage.png` — MITRE ATT&CK coverage map
- [ ] `05-response-actions.png` — Response actions history
- [ ] `06-real-time-response.png` — RTR session screen (even if no commands run)
