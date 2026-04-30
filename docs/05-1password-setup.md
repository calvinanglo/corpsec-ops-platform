# 1Password Business Setup Guide

## Sign-Up

https://1password.com/business — 14-day Business trial (no credit card).

## Create Vault Structure

Admin Console → Vaults → Create vault for each:
- **SOC-Shared** — Shared SOC team credentials (Wazuh admin, Grafana admin)
- **IT-Admin** — Privileged IT admin credentials
- **Service-Accounts** — API tokens, service account keys
- **Personal** — Per-user personal vaults (auto-created via SCIM)

## Configure SCIM Provisioning from Okta

1. 1Password Admin Console → Integrations → SCIM
2. Generate SCIM token + URL
3. In Okta: Applications → Add Application → search "1Password" → install official integration
4. Enter SCIM token + URL from step 2
5. Provisioning → Enable Push Users, Push Groups
6. Assign Okta groups to provision (soc-analyst, soc-lead, etc.)

## Set Up Service Account for API Automation

1. Admin Console → Integrations → Service Accounts → New
2. Name: `corpsec-ops-platform`
3. Vault access: Read-only on `Service-Accounts` vault
4. Save Service Account token

## Set Up Events Reporting API (separate from CLI)

1. Admin Console → Integrations → Events Reporting → Generate token
2. Save to `.env`:
   ```
   OP_SERVICE_ACCOUNT_TOKEN=<service_account_token>
   OP_AUDIT_LOG_API_KEY=<events_api_token>
   OP_VAULT=SOC-Shared
   ```

## Install 1Password CLI in corpsec-python container

Already in `python/Dockerfile`:
```dockerfile
RUN curl -sSO https://downloads.1password.com/linux/keys/1password.asc && \
    cat 1password.asc | gpg --dearmor > /usr/share/keyrings/1password-archive-keyring.gpg && \
    echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/1password-archive-keyring.gpg] https://downloads.1password.com/linux/debian/amd64 stable main' \
      > /etc/apt/sources.list.d/1password.list && \
    apt-get update && apt-get install -y 1password-cli
```

## Verify

```bash
docker exec corpsec-python op vault list
make sync-1password
# Should pull recent audit, signin, item_usage events
```

## Required Screenshots

- [ ] `01-business-console.png` — Business admin console home
- [ ] `02-vault-structure.png` — Vault list with categories
- [ ] `03-okta-sso-integration.png` — SCIM provisioning page
- [ ] `04-watchtower.png` — Watchtower with breached/weak password reports
- [ ] `05-audit-events.png` — Audit events stream
- [ ] `06-secret-automation.png` — Service account API access page
