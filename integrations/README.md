# Real Production Tool Integrations

This directory holds **setup walkthroughs** and **configuration exports** for
each real production tool. The actual API client code lives in
[`../python/integrations/`](../python/integrations/).

## Tool Setup Walkthroughs

| Tool | Setup Doc | API Code | Wazuh Rules |
|------|-----------|----------|-------------|
| Okta Developer Free | [`../docs/02-okta-setup.md`](../docs/02-okta-setup.md) | [`../python/integrations/okta/`](../python/integrations/okta/) | [`../wazuh/custom-rules/okta-rules.xml`](../wazuh/custom-rules/okta-rules.xml) |
| CrowdStrike Falcon | [`../docs/03-crowdstrike-setup.md`](../docs/03-crowdstrike-setup.md) | [`../python/integrations/crowdstrike/`](../python/integrations/crowdstrike/) | [`../wazuh/custom-rules/crowdstrike-rules.xml`](../wazuh/custom-rules/crowdstrike-rules.xml) |
| Google Workspace | [`../docs/04-gws-setup.md`](../docs/04-gws-setup.md) | [`../python/integrations/google_workspace/`](../python/integrations/google_workspace/) | [`../wazuh/custom-rules/gws-rules.xml`](../wazuh/custom-rules/gws-rules.xml) |
| 1Password Business | [`../docs/05-1password-setup.md`](../docs/05-1password-setup.md) | [`../python/integrations/onepassword/`](../python/integrations/onepassword/) | [`../wazuh/custom-rules/onepassword-rules.xml`](../wazuh/custom-rules/onepassword-rules.xml) |
| Microsoft Intune | [`../docs/06-intune-setup.md`](../docs/06-intune-setup.md) | [`../python/integrations/intune/`](../python/integrations/intune/) | [`../wazuh/custom-rules/intune-rules.xml`](../wazuh/custom-rules/intune-rules.xml) |

## Configuration Exports

Subdirectories contain JSON exports of policies/rules from each tool, useful for:
- Version-controlling production configs
- Comparing baseline vs. current state
- Sharing configurations across tenants

For example: `intune/compliance_policies/windows-compliance.json` is the exported
JSON of an Intune compliance policy that can be re-imported into a fresh tenant.
