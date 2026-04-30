# PHISH-001: Phishing Campaign Execution

| Frequency | Owner |
|-----------|-------|
| Monthly | Phishing Admin / SOC L2 |

## Pre-Campaign Setup (One-Time)

1. GoPhish admin UI: `http://corpsec.local:3333`
2. Create user groups from Okta:
   ```bash
   docker exec corpsec-python python -c "
   from integrations.okta.okta_client import OktaClient
   from integrations.gophish_client import GoPhishClient
   okta = OktaClient()
   gp = GoPhishClient()
   users = okta.export_users_and_roles()['users']
   # Create GoPhish group from Okta users
   "
   ```
3. Configure SMTP profile:
   - Name: `MailHog`
   - Host: `mailhog:1025` (no auth, no TLS — local-only sandbox)
4. Import templates from `gophish/templates/email-templates/`
5. Import landing pages from `gophish/templates/landing-pages/`

## Monthly Campaign Workflow

### Week 1: Plan
- Choose campaign theme from rotation:
  - Month 1: Credential Harvest (Okta password reset)
  - Month 2: Malicious Attachment (Q4 financial report)
  - Month 3: CEO Fraud / BEC (wire transfer request)
- Pick target group (rotate departments)
- Draft custom variations of email templates if needed

### Week 2: Schedule
1. In GoPhish: Campaigns → New Campaign
2. Select template, landing page, group, SMTP profile
3. Schedule launch:
   - Stagger over 2 weeks (10% of users per day)
   - Avoid Mondays (high inbox volume) and Fridays (people leaving early)

### Week 3: Monitor
- Daily check of Grafana `Phishing Campaigns` dashboard
- Review GoPhish results in real-time
- Triage any user reports via the Phish Alert button (separate from the simulation)

### Week 4: Education + Report
1. **Pull results**:
   ```bash
   docker exec corpsec-python python -m integrations.gophish_client results
   ```

2. **Identify failure patterns**:
   - Per-department failure rate
   - Repeat offenders (failed 2+ campaigns)
   - Time-to-click distribution

3. **Trigger education**:
   - Users who clicked → automatic redirect to training page (already done)
   - Repeat offenders → manager-led 1:1 conversation
   - Department-level high failure → targeted training session

4. **Report to leadership**:
   - Monthly metrics in Grafana
   - Quarterly trend analysis
   - Comparison to industry benchmarks (KnowBe4, Proofpoint published rates)

## Real Phishing Report Handling

**Important**: When a user reports a real phishing email (not from the simulation):

1. n8n workflow `phishing-report-triage` auto-creates a TheHive case
2. Follow `IR-001-phishing-response.md` runbook
3. Do NOT confuse with simulation results — simulation links go to GoPhish landing pages, real attacks don't

## Metrics Targets

| Metric | Target | Industry Baseline |
|--------|--------|-------------------|
| Click rate | <10% | ~25% (untrained orgs) |
| Credential submission rate | <2% | ~10% |
| Report rate (Phish Alert button) | >30% | ~15% |
| Time to first report | <5 min | ~30 min |

## Annual Review

- Compare year-over-year metrics
- Update training content based on real attack TTPs observed
- Recalibrate severity thresholds in `python/dlp/policies.py` based on phishing trends
