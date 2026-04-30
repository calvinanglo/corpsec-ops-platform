# Risk Register

ISMS risk register format aligned with ISO 27001:2022 risk treatment plan.
Update at minimum quarterly. New risks must be entered within 5 business days
of identification.

| Risk ID | Asset | Threat | Vulnerability | Likelihood | Impact | Risk Rating | Treatment | Control(s) | Residual Risk | Owner | Review Date |
|---------|-------|--------|---------------|------------|--------|-------------|-----------|------------|---------------|-------|-------------|
| R-001   | Customer PII data | External attacker | Web app SQL injection | Medium | High | High | Mitigate | A.14.2.5 secure development; pen test | Low | AppSec Lead | 2026-Q3 |
| R-002   | Privileged Okta accounts | Credential phishing | Lack of MFA enforcement | High | High | Critical | Mitigate | A.9.4 MFA enforced via Okta sign-on policy | Low | IAM Admin | 2026-Q3 |
| R-003   | Endpoint workstations | Ransomware | Unpatched OS vulnerabilities | Medium | High | High | Mitigate | A.12.6 vuln mgmt + EDR (CrowdStrike) | Low | SOC Lead | 2026-Q3 |
| R-004   | Customer data in cloud storage | Insider data exfil | Lack of DLP controls | Medium | High | High | Mitigate | A.13.2 DLP engine + AI exfil detection | Medium | SOC Lead | 2026-Q3 |
| R-005   | Audit log integrity | Log tampering | Insufficient log forwarding | Low | Medium | Medium | Mitigate | A.12.4 centralized SIEM (Wazuh) | Low | SOC Lead | 2026-Q3 |

## Rating Matrix

|             | Low Impact | Medium Impact | High Impact |
|-------------|------------|---------------|-------------|
| **Low Likelihood**    | Low | Low | Medium |
| **Medium Likelihood** | Low | Medium | High |
| **High Likelihood**   | Medium | High | Critical |

## Treatment Strategies

| Treatment | When to use |
|-----------|-------------|
| **Mitigate** | Reduce likelihood or impact via controls |
| **Transfer** | Insurance, contractual liability shift, third-party SaaS |
| **Accept** | Risk is below tolerance threshold; documented acceptance |
| **Avoid** | Discontinue activity that creates the risk |

## Linkage to Controls

Each risk's `Control(s)` column references one or more entries in:
- [`compliance/control-mapping/iso27001-controls.yml`](../control-mapping/iso27001-controls.yml)
- [`compliance/control-mapping/soc2-controls.yml`](../control-mapping/soc2-controls.yml)

## Review Cadence

- **Quarterly**: All risks reviewed for changes in likelihood/impact
- **On Material Change**: New asset added, threat landscape shift, control failure
- **Post-Incident**: Update affected risks within 7 days of incident closure
