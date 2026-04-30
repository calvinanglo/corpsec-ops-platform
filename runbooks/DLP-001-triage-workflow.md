# DLP-001: DLP Triage Workflow

Quick-reference card for L1 analysts triaging DLP alerts in the queue.

## Goal

Resolve every DLP alert in the queue within SLA:
- MEDIUM: 4 hours
- HIGH: 1 hour
- CRITICAL: 30 minutes

## Step-by-step

1. **Sort the queue** by severity (CRITICAL → HIGH → MEDIUM)
2. **Open the top alert** in TheHive
3. **Run the signal-vs-noise checklist** from `IR-003-data-loss-triage.md`
4. **Decide and document**:
   - True positive → follow IR-003 containment
   - False positive → tune `python/dlp/policies.py`, document in case, close
   - Need more info → assign to L2 with specific question
5. **Close the case** with proper tags for trend analysis

## Tuning a False Positive

```python
# In python/dlp/policies.py, find the offending policy and add to false_positive_patterns:
PII_001_SSN.false_positive_patterns.append(
    _re(r"order[#:\s]*\d{3}[-\s]\d{2}[-\s]\d{4}")
)
```

Then redeploy:
```bash
docker compose restart corpsec-python
```

Verify by re-scanning the same content:
```bash
docker exec corpsec-python python -m dlp.engine --file /testdata/<file>
```

## Common False Positive Patterns

| Policy | Common FP source | Suggested suppression |
|--------|------------------|----------------------|
| PII-001 (SSN) | Phone numbers, order numbers, ISBNs | Already suppressed; add domain-specific orders |
| PII-002 (CC) | Test card numbers | Already suppressed |
| PII-003 (bulk email) | Marketing list, customer roster (legitimate) | Add file path exclusion |
| LEGAL-001 | Sample contract templates | Add filename pattern `template_*.docx` |
| CODE-001 | Documentation showing example keys | Already suppressed via `EXAMPLE`, `<your...>` |

## Quality Metrics (track for SOC report)

- **Triage time**: minutes from case creation to first action
- **Resolution time**: minutes to close
- **False positive rate**: FP closures / total closures
- **Tuning rate**: % of FPs that resulted in policy update (target: 100%)
