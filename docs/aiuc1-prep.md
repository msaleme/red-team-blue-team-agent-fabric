# AIUC-1 Pre-Certification Readiness Tool

Maps Agent Security Harness results to AIUC-1 certification requirements and generates a readiness report.

## Overview

The AIUC-1 standard defines 20 testable requirements across 5 categories. Our harness covers **15 of 20** (75%):

| Category | Requirements | Coverage |
|----------|-------------|----------|
| Security (B001-B005) | 5 | 5/5 (100%) |
| Reliability (C001-C010) | 10 | 10/10 (100%) |
| Transparency (D001-D004) | 4 | 4/4 (100%) |
| Safety (E001-E003) | 3 | 0/3 (gap) |
| Content Safety (F001-F002) | 2 | 0/2 (gap) |

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

The full mapping is in `configs/aiuc1_mapping.yaml`. Key mappings:

- **Security (B001-B005)**: MCP harness (MCP-001 to MCP-010) + Identity harness (ID-001 to ID-018)
- **Reliability (C001-C010)**: A2A harness (A2A-001 to A2A-012) + AIUC-1 compliance tests + L402 tests
- **Transparency (D001-D004)**: Attestation module + Provenance harness + Identity audit tests
- **Safety (E001-E003)**: AIUC-1 compliance harness (simulation only - gap)
- **Content Safety (F001-F002)**: CBRN tests in AIUC-1 compliance harness (simulation only - gap)

## Closing Gaps

### Safety (E001-E003)
The `aiuc1_compliance_harness.py` includes simulation-mode tests for incident response. To close this gap:
1. Deploy actual incident response infrastructure (circuit breakers, kill switches)
2. Run tests against real endpoints with `--url` instead of `--simulate`
3. Validate audit trail integration with production logging

### Content Safety (F001-F002)
1. **F001 (Harmful Content Filtering)**: Build a dedicated content classification test suite
2. **F002 (CBRN)**: Run existing CBRN tests against production LLM endpoints

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
