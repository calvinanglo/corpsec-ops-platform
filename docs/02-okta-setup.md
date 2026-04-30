# Okta Setup Guide

## Sign-Up

See [`01-trial-signup-guide.md`](01-trial-signup-guide.md) — choose **Integrator Free Plan**.

## Configure Apps for SSO

For each self-hosted service that needs SSO, create an OIDC application in Okta:

### Grafana
1. Admin Console → Applications → Add Application → OIDC - OpenID Connect → Web Application
2. Sign-in redirect URI: `https://corpsec.local:3443/login/generic_oauth`
3. Sign-out redirect URI: `https://corpsec.local:3443/`
4. Save Client ID + Client Secret to `.env`:
   ```
   GF_AUTH_GENERIC_OAUTH_CLIENT_ID=<client_id>
   GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET=<client_secret>
   GF_AUTH_GENERIC_OAUTH_AUTH_URL=https://dev-XXXXXX.okta.com/oauth2/default/v1/authorize
   GF_AUTH_GENERIC_OAUTH_TOKEN_URL=https://dev-XXXXXX.okta.com/oauth2/default/v1/token
   GF_AUTH_GENERIC_OAUTH_API_URL=https://dev-XXXXXX.okta.com/oauth2/default/v1/userinfo
   ```

### TheHive
1. New OIDC Application
2. Redirect URI: `https://corpsec.local:9443/auth/oauth2/callback`
3. Update TheHive `application.conf` with client ID/secret

## Create Custom Groups

Match the SOC team structure:
- `soc-analyst` (L1)
- `soc-lead` (L2)
- `compliance-admin`
- `security-engineer`
- `phishing-admin`

Assign these groups to the OIDC apps so role mapping works in Grafana
(soc-lead → Admin, compliance-admin → Editor, soc-analyst → Viewer).

## Create API Token

Admin Console → Security → API → Tokens → Create Token

Save to `.env`:
```
OKTA_API_TOKEN=<token>
```

## Verify

```bash
make sync-okta
# Should pull recent system log events to /var/log/corpsec/okta-events.jsonl
```

## Required Screenshots

- [ ] `01-admin-console.png` — Admin Console home
- [ ] `02-sso-applications.png` — Applications list with OIDC apps
- [ ] `03-mfa-policy.png` — MFA enrollment policy detail
- [ ] `04-system-log-events.png` — System Log with recent events
- [ ] `05-scim-provisioning.png` — Provisioning page for 1Password
- [ ] `06-conditional-access.png` — Sign-on policy with grant controls
