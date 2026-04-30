# Microsoft Intune Setup Guide

## Sign-Up

https://signup.microsoft.com/get-started/signup?products=cfq7ttc0lcs7%3a0001 — 30-day trial.

This creates a Microsoft 365 tenant with Intune license.

## Initial Configuration

1. Log in to https://endpoint.microsoft.com (Intune admin center)
2. Set MDM authority: should already be Intune by default for new tenants

## Create Compliance Policies

### Windows Compliance Policy
1. Devices → Compliance policies → Create → Windows 10 and later
2. Settings:
   - **Device Health**: BitLocker required, Secure Boot required
   - **Device Properties**: Min OS version 10.0.19041 (20H1)
   - **System Security**: Password required (8+ chars, complex), encryption required, antivirus required
3. Assignments: All devices

### macOS Compliance Policy
1. Devices → Compliance policies → Create → macOS
2. Settings:
   - **System Security**: FileVault required, password complexity
   - **Device Properties**: Min OS version 13.0
3. Assignments: All devices

### iOS Compliance Policy
1. Devices → Compliance policies → Create → iOS/iPadOS
2. Settings:
   - **Device Health**: Jailbroken devices blocked
   - **Device Properties**: Min OS 16.0
3. Assignments: All devices

## Create Conditional Access Policies

Azure Portal → Entra ID → Security → Conditional Access → New policy

### CA-001: Require Compliant Device for Corporate Apps
- Users: All users (exclude break-glass admin)
- Apps: Office 365, Salesforce, etc.
- Conditions: Device platforms (Windows, macOS, iOS, Android)
- Grant: Require device to be marked as compliant

### CA-002: Block Legacy Authentication
- Users: All
- Conditions: Client apps = Legacy authentication clients
- Grant: Block access

### CA-003: Require MFA from non-corporate IPs
- Users: All
- Conditions: Locations = Any location (exclude trusted IP ranges)
- Grant: Require MFA

## Configure App Registration for Graph API

1. Azure Portal → Entra ID → App registrations → New registration
2. Name: `corpsec-ops-platform`
3. Single tenant
4. After creation, save: Application (client) ID, Directory (tenant) ID
5. Certificates & secrets → New client secret → save value (shown only once)
6. API permissions → Microsoft Graph → Application permissions:
   - `DeviceManagementManagedDevices.Read.All`
   - `DeviceManagementConfiguration.Read.All`
   - `Policy.Read.All`
   - `AuditLog.Read.All`
7. Grant admin consent

## Configure .env

```
INTUNE_TENANT_ID=<tenant_id>
INTUNE_CLIENT_ID=<client_id>
INTUNE_CLIENT_SECRET=<secret>
GRAPH_API_BASE_URL=https://graph.microsoft.com/v1.0
```

## Enroll Test Device

Choose one:
- **Windows VM**: Settings → Accounts → Access work or school → Connect → enter trial admin credentials
- **Android phone (your own)**: Install Intune Company Portal app → enroll
- **iOS (your own)**: Install Intune Company Portal app → enroll
- **macOS**: Install Company Portal from Mac App Store → enroll

## Verify

```bash
make sync-intune
# Should pull device list to /var/log/corpsec/intune-events.jsonl
```

## Required Screenshots

- [ ] `01-admin-center.png` — Intune admin center home
- [ ] `02-device-enrollment.png` — Devices list with your enrolled device
- [ ] `03-compliance-policies.png` — Compliance policy detail
- [ ] `04-conditional-access.png` — CA policy with grant controls
- [ ] `05-app-deployment.png` — App deployment status
- [ ] `06-configuration-profiles.png` — Configuration profile (Wi-Fi/VPN)
- [ ] `07-endpoint-security.png` — Endpoint security baseline page
