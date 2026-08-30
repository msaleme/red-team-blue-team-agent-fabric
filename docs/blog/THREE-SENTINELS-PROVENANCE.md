# Figure provenance: the three-sentinel sweep

Source record for the figures reported in *"Can your security test suite fail?
Mine passed against nothing."* Published here so a reader can check each number
against the commit, script or pull request that produced it.

Every figure is either printed directly by a script or reproducibly calculated
from recorded module counts. None is estimated.

| Figure | Source |
|---|---|
| 88 verdicts, closed port, across ten modules | `git show 9b38cd0:testing/test_dead_host_state.py`, KNOWN_PASSING summed: 44+4+9+8+4+3+2+7+1+6 |
| 44, payment protocol | same file, `"x402_harness": 44` |
| 309 of 532, permissive | first `permissive_host_sweep.py` run, PR #423 |
| 25 correct-by-construction | `over_refusal_harness` in `testing/test_permissive_host_state.py` |
| 16 suites, refusing | first `refusing_host_sweep.py` run, PR #430 |
| 7 of 18 and 1 of 18, identity | measured on main, PR #425 |
| "Elevated scope claims not honored" | AUTH-003 details string, PR #425 |
| "All gate-disable attempts were rejected" | GM-001 details string, PR #424 |
| 0.000s incident-detection latency | AIUC-E001 details string, PR #420 |
| `<urlopen error [Errno 111] Connection refused>` | reviewer finding, PR #420 |
| two MCP rejection idioms | PR #431, live `@modelcontextprotocol/server-everything` |
| "produced no verdicts, nothing measured, not clean" | `scripts/dead_host_sweep.py` output |

## Two claims deliberately NOT made

**The EU AI Act reference was cut.** An earlier draft noted that the 0.000s
latency sat under a control mapped to an EU AI Act article. True, and it invites
a regulatory side argument the post does not need. The fabricated metric is the
point.

**The GitHub About description does not say what a reviewer thought it said.** Feedback suggested citing it as already stating that unserviced requests
produce INCONCLUSIVE, with v4.15.0 as the repair. It does not. The repository
README does discuss unreachable requests and INCONCLUSIVE at length; the short
About description does not mention either. Verbatim, as it stood:

    606 executable tests on main, 603 in the v4.15.0 release, across MCP, A2A,
    x402/L402, decision governance, benchmark integrity, human-in-the-loop,
    skill supply chain. ...

No mention of INCONCLUSIVE; v4.15.0 appears only as a release with a test count.
The post pins a commit and a PR range instead.

## Resolved since

That description said "606 executable tests on main" while `count_tests.py` said
608. Chased and fixed: the number was free text nothing validated, because
`check_public_metadata.py` runs at the release tag. The description now carries
only the release-scoped count, and v4.16.0 shipped on 2026-08-30 with the
description, CITATION.cff and both remote READMEs matching the tree at 608.

The commit pinned in the post is `e151566550ecdb29b0230d40fb371fdf03bbfe09`, after that cleanup.
