# SOC 2 Evidence Cover Sheet — `<CONTROL_ID>`

| Field | Value |
|-------|-------|
| **Control ID** | `<CC6.1 / CC6.2 / etc.>` |
| **Control Name** | `<from compliance/control-mapping/soc2-controls.yml>` |
| **Trust Services Criterion** | `<Security / Availability / Confidentiality / etc.>` |
| **Collection Date** | `YYYY-MM-DD` |
| **Collection Period** | `YYYY-MM-DD to YYYY-MM-DD` |
| **Evidence Type** | `<Configuration export / Log query / Dashboard screenshot / Policy doc>` |
| **Source System** | `<Okta / CrowdStrike / Wazuh / TheHive / etc.>` |
| **Collector** | `<automated (corpsec-python) / manual>` |
| **Operator** | `<analyst@corpsec.local>` |
| **SHA-256 of Artifact** | `<hex>` |

## Control Statement

`<Verbatim from SOC 2 framework — what the control requires>`

## Implementation Description

`<How the platform implements this control. Reference specific files, configs, runbooks.>`

Example:
> CC6.2 — Authentication is enforced through Okta MFA. All users are required
> to enroll a TOTP factor at first sign-in. Sign-on policies require MFA for any
> access from outside the corporate IP range. Evidence: Okta MFA policy export
> (attached) shows `factorRequired: true` for all groups.

## Evidence Artifacts

| File | Description | SHA-256 |
|------|-------------|---------|
| `evidence-1738339565.json` | Okta MFA policy export | `<hash>` |
| `screenshot-mfa-policy.png` | Admin Console screenshot | `<hash>` |

## Operating Effectiveness

- [ ] Control is implemented as designed
- [ ] Control operated continuously during the audit period
- [ ] Exceptions noted and remediated within SLA

## Exceptions / Deviations

`<None / list any failures and remediation actions taken>`

## Reviewer Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Compliance Admin | | | |
| Control Owner | | | |
| Internal Audit | | | |
