# Google Workspace Setup Guide

## Sign-Up

https://workspace.google.com/business/signup/welcome — Business Standard 14-day trial.

## Create Test Users

Admin Console → Directory → Users → Add new user (create 5):
- soc-analyst@<domain>
- soc-lead@<domain>
- compliance-admin@<domain>
- security-engineer@<domain>
- testuser@<domain>

## Enable Security Center

Admin Console → Security → Security Center → Enable.

## Create DLP Rule

Admin Console → Security → Data protection → Create rule:
- Name: `corpsec-pii-credit-card`
- Apply to: Drive
- Conditions: detect Credit card numbers (high confidence)
- Action: Warn user + log incident

## Configure Service Account for API Access

1. Google Cloud Console → IAM & Admin → Service Accounts → Create
2. Name: `corpsec-ops-platform`
3. Grant role (project-level): none needed
4. After creation: Service Account → Keys → Add Key → JSON → save as `gws-service-account.json`
5. Note the unique numeric ID of the service account (Client ID)

6. Admin Console → Security → Access and data control → API controls → Domain-wide Delegation
7. Add new: Client ID = numeric ID from step 5
8. Scopes (one per line):
   ```
   https://www.googleapis.com/auth/admin.reports.audit.readonly
   https://www.googleapis.com/auth/admin.reports.usage.readonly
   https://www.googleapis.com/auth/admin.directory.user.readonly
   https://www.googleapis.com/auth/apps.alerts
   ```

## Configure .env

```
GWS_DOMAIN=<your-trial-domain>
GWS_SERVICE_ACCOUNT_FILE=/run/secrets/gws-service-account.json
GWS_DELEGATED_USER=admin@<your-trial-domain>
```

Mount the service account file in docker-compose.soar.yml secrets section:
```yaml
secrets:
  gws-service-account:
    file: ./secrets/gws-service-account.json
```

## Federate SSO with Okta

GWS Admin Console → Security → Single sign-on with third-party IdP → SAML configuration with Okta IdP metadata XML.

## Verify

```bash
make sync-gws
# Should pull recent audit events from login, admin, drive, token, user_accounts apps
```

## Required Screenshots

- [ ] `01-admin-console.png` — Admin console home
- [ ] `02-security-center.png` — Security Center dashboard
- [ ] `03-alert-center.png` — Alert Center with at least one alert
- [ ] `04-dlp-rules.png` — DLP rule configuration screen
- [ ] `05-audit-logs.png` — Audit log query result
- [ ] `06-context-aware-access.png` — Context-Aware Access policy
