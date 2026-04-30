# Trial Sign-Up Guide

Sign up for **all 5 trials in one session (~90 minutes)** to start the clocks
in parallel. Document each trial's start date below for screenshot deadline tracking.

## Sign-Up Order

| Order | Tool | Duration | Difficulty | URL |
|-------|------|----------|-----------|-----|
| 1 | **Okta Developer** | No expiry | Easy | https://developer.okta.com/signup/ |
| 2 | **Microsoft Intune** | 30 days | Medium | https://signup.microsoft.com/get-started/signup?products=cfq7ttc0lcs7%3a0001 |
| 3 | **Google Workspace** | 14 days | Easy | https://workspace.google.com/business/signup/welcome |
| 4 | **CrowdStrike Falcon** | 14 days | Easy | https://www.crowdstrike.com/products/free-trial/ |
| 5 | **1Password Business** | 14 days | Easy | https://1password.com/business |

## 1. Okta Developer (PERMANENT — no expiry)

1. Go to https://developer.okta.com/signup/
2. Choose **Integrator Free Plan** (not the 30-day org)
3. Use a **business-looking email** (e.g., your name @ a domain you own — Okta blocks gmail.com)
4. Verify email, set admin password
5. Note your org URL: `https://dev-XXXXXX.okta.com`
6. Generate API token: Admin Console → Security → API → Tokens → Create Token
7. **Save to .env**:
   ```
   OKTA_ORG_URL=https://dev-XXXXXX.okta.com
   OKTA_API_TOKEN=<token>
   ```
8. **Screenshot now**: Admin console home page (`screenshots/okta/01-admin-console.png`)

## 2. Microsoft Intune (30 days)

1. Go to https://signup.microsoft.com/get-started/signup?products=cfq7ttc0lcs7%3a0001
2. Provide business details (use your own info — no fictitious data)
3. Choose a domain: `<yourname>corpsecops.onmicrosoft.com`
4. Set admin credentials
5. Once tenant is created (5 min), go to https://endpoint.microsoft.com
6. **Screenshot**: Admin center home (`screenshots/intune/01-admin-center.png`)
7. Configure App Registration for Graph API access:
   - Azure Portal → Entra ID → App registrations → New
   - Name: `corpsec-ops-platform`
   - Supported account types: Single tenant
   - Note: Application (client) ID, Directory (tenant) ID
   - Certificates & secrets → New client secret → save value (shown once)
   - API permissions → Microsoft Graph → Application permissions:
     - `DeviceManagementManagedDevices.Read.All`
     - `DeviceManagementConfiguration.Read.All`
     - `Policy.Read.All`
   - Grant admin consent
8. **Save to .env**:
   ```
   INTUNE_TENANT_ID=<tenant_id>
   INTUNE_CLIENT_ID=<client_id>
   INTUNE_CLIENT_SECRET=<secret>
   ```

## 3. Google Workspace (14 days)

1. Go to https://workspace.google.com/business/signup/welcome
2. Sign up with same business details
3. Verify domain (use a domain you control, or use the `*.corpsecops.com` redirect Google offers)
4. Create test users — at least 5 (matches Okta user count)
5. Enable Security Center: Admin Console → Security → Security Center
6. Create test DLP rule: Security → DLP → Create rule
7. **Screenshots**:
   - Admin console home (`screenshots/google-workspace/01-admin-console.png`)
   - Security Center dashboard
   - DLP rule configuration
8. Configure service account for API:
   - Google Cloud Console → IAM → Service Accounts → Create
   - Grant role: `roles/admin.directory.user.readonly`
   - Generate JSON key → save as `gws-service-account.json`
   - Domain-wide delegation: Admin Console → Security → API Controls → Domain-wide Delegation → Add API client with the scopes from `python/integrations/google_workspace/gws_admin_client.py`

## 4. CrowdStrike Falcon (14 days)

1. Go to https://www.crowdstrike.com/products/free-trial/
2. Submit form (business email, role, etc.)
3. Wait for approval email (usually within 24h)
4. Once approved: download Falcon sensor for at least 1 endpoint (your laptop or a Win VM)
5. Install sensor with the customer ID provided
6. **Screenshot**: Falcon dashboard (`screenshots/crowdstrike/01-falcon-dashboard.png`)
7. Configure API access:
   - Falcon Console → Support → API Clients and Keys → Create API Client
   - Scopes: Detections, Hosts, Real-Time Response (read-only)
   - Save Client ID + Client Secret
8. **Save to .env**:
   ```
   CROWDSTRIKE_CLIENT_ID=<id>
   CROWDSTRIKE_CLIENT_SECRET=<secret>
   ```
9. Trigger test detection (eicar test file):
   ```powershell
   Set-Content -Path "$env:USERPROFILE\Desktop\eicar.txt" -Value 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
   ```

## 5. 1Password Business (14 days)

1. Go to https://1password.com/business
2. Click "Try free for 14 days"
3. Provide business details
4. **No credit card required**
5. Set up your account
6. **Screenshots**:
   - Business console (`screenshots/1password/01-business-console.png`)
   - Vault list
7. Create vault structure:
   - SOC-Shared
   - IT-Admin
   - Service-Accounts
   - Personal
8. Configure SCIM with Okta (Admin Console → Provisioning → SCIM)
9. Generate Service Account token for API: Admin → Integrations → Service Accounts
10. **Save to .env**:
    ```
    OP_SERVICE_ACCOUNT_TOKEN=<token>
    OP_AUDIT_LOG_API_KEY=<events_api_key>
    ```

## Trial Tracking Sheet

Fill this in immediately after sign-up:

| Tool | Trial start date | Expires | Critical screenshots done? |
|------|------------------|---------|----------------------------|
| Okta Developer | YYYY-MM-DD | NEVER | ☐ |
| Microsoft Intune | YYYY-MM-DD | +30 days | ☐ |
| Google Workspace | YYYY-MM-DD | +14 days | ☐ |
| CrowdStrike Falcon | YYYY-MM-DD | +14 days | ☐ |
| 1Password Business | YYYY-MM-DD | +14 days | ☐ |

## Post-Sign-Up Verification

```bash
# Verify all credentials work
docker compose -f docker-compose.yml -f docker-compose.soar.yml up -d
make sync-all      # Should pull events from all 5 tools without auth errors
```

If any sync fails, check the relevant `.env` variables and the corresponding
setup doc (`docs/02-okta-setup.md` through `docs/06-intune-setup.md`).
