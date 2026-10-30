# AIUC-1 Pre-Certification Readiness Tool

Maps Agent Security Harness results to AIUC-1 certification requirements and generates a readiness report.

## Overview

The tool reads the requirement-to-test mapping in `configs/aiuc1_mapping.yaml` and reports, for each listed
AIUC-1 requirement, which named tests ran and how they resolved. The mapping lists 23 of the 50 active
requirements in the AIUC-1 release of 2026-10-15 (19 with named tests, 4 marked GAP); see
[the crosswalk](AIUC1-CROSSWALK.md) for every row, its title as published, and its stated limit.

A readiness report is E1 material: it shows which harness tests map to a requirement and what they returned
against the target you ran. It is not a certification, a third-party evaluation, or a finding that a
requirement is met. No coverage percentage is claimed.

> **Correction (2026-10-30):** this page previously said the standard "defines 20 testable requirements" and that
> the harness "covers 19 of 20 (95%)", with category names (for example "Transparency (D001-D004)") that are not
> AIUC-1's. Those were wrong; see the CHANGELOG entry for the corrected mapping.

## Quick Start

```bash
# Option 1: Use existing harness report files
python scripts/aiuc1_prep.py --reports reports/mcp-report.json

# Option 2: Run harness against a live target
python scripts/aiuc1_prep.py --url http://localhost:8080/mcp

# Option 3: Simulation mode (no live target needed)
python scripts/aiuc1_prep.py --simulate
```

## Usage

### Using Pre-existing Reports

If you've already run harness tests and have JSON report files:

```bash
python scripts/aiuc1_prep.py --reports \
    reports/mcp-report.json \
    reports/a2a-report.json \
    reports/identity-report.json
```

### Running Against a Live Target

```bash
# Default suites (MCP, A2A, Identity)
python scripts/aiuc1_prep.py --url https://my-agent.example.com/mcp

# Specific suites
python scripts/aiuc1_prep.py --url https://my-agent.example.com/mcp \
    --suites mcp a2a identity l402 provenance
```

### Output Options

```bash
# Custom output directory
python scripts/aiuc1_prep.py --simulate --output-dir my-reports/

# Also generate machine-readable JSON
python scripts/aiuc1_prep.py --simulate --json
```

## Output

The tool generates:

1. **Markdown Report** at `reports/aiuc1-prep-YYYY-MM-DD.md`:
   - Executive summary with readiness score
   - Per-category breakdown with pass/fail status
   - Gap analysis with recommendations
   - Next steps to close gaps

2. **JSON Report** (with `--json` flag) at `reports/aiuc1-prep-YYYY-MM-DD.json`:
   - Machine-readable version of the same data
   - Suitable for CI/CD integration

## Requirement Status Codes

| Status | Meaning |
|--------|---------|
| **COVERED+PASS** | Harness tests exist and all pass |
| **COVERED+FAIL** | Harness tests exist but some fail |
| **COVERED (no results)** | Tests defined but not included in this run |
| **NOT YET COVERED** | Gap - no production-ready tests yet |

## Requirement Mapping

The full mapping is in `configs/aiuc1_mapping.yaml`, and [the crosswalk](AIUC1-CROSSWALK.md) renders it as a
table. Requirement IDs and titles are copied from the pinned snapshot `configs/aiuc1_standard_2026-10-15.json`;
`tests/test_aiuc1_mapping_matches_standard.py` fails if they drift from it.

## Closing Gaps

The four GAP rows (C001, C002, E004, E006) are documentation, process or organisational requirements that an
adversarial test harness cannot evidence. 27 further active requirements are not listed for the same reason.
For the E001-E003 failure-plan requirements, the named tests (IR-001 to IR-003, AIUC-E001 to AIUC-E003, HALL-001,
HALL-002) check that the response behaviour occurs during an incident; they do not evidence the written plan.

## CI/CD Integration

```yaml
# Example GitHub Actions step
- name: AIUC-1 Readiness Check
  run: |
    python scripts/aiuc1_prep.py \
      --reports reports/latest-scan.json \
      --json \
      --output-dir reports/
    # Parse JSON for CI gate
    python -c "
    import json, sys
    r = json.load(open('reports/aiuc1-prep-*.json'))
    if r['summary']['gaps'] > 5:
        print('Too many gaps for certification')
        sys.exit(1)
    "
```
