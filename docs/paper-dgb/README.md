# Decision Governance Benchmark — arXiv Paper

LaTeX source for: *Decision Governance Benchmark: Executable Behavioral Tests
for Autonomous AI Agent Security* (Saleme 2026).

**Target:** arXiv CS.CR (primary). (The NeurIPS 2026 Evaluations & Datasets stretch track's May 6 2026 deadline has passed without a submission — dropped as a target.)

---

## Compiling

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

Three passes are required: the first generates `.aux`, `bibtex` resolves
citations, and the final two passes resolve cross-references.

**Output:** `main.pdf`

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `geometry` | 1-inch margins |
| `booktabs` | Publication-quality tables |
| `hyperref` | PDF hyperlinks and metadata |
| `amsmath` / `amssymb` | Math notation |
| `natbib` | Author-year and numeric citation styles |
| `microtype` | Microtypographic refinements |
| `xcolor` | Color support |
| `array` | Extended column formatting |
| `multirow` | Multi-row table cells |
| `longtable` | Multi-page appendix table (Table~\ref{tab:appendix-cases}) |
| `pifont` | ✓/✗ symbols (`\ding{51}`/`\ding{55}`) in the appendix table |
| `tikz` (+ `arrows.meta`, `positioning` libraries) | Pipeline architecture figure (Figure~\ref{fig:pipeline}) |

All packages are included in TeX Live (full) and MikTeX. No custom `.sty`
files are required — the paper uses the standard `article` class with
`[10pt,twocolumn]` options, which is the standard arXiv CS submission format.

---

## File List

| File | Description |
|------|-------------|
| `main.tex` | Full paper source |
| `references.bib` | BibTeX bibliography (16 entries) |
| `_gen_appendix.py` | Regenerates Appendix~A's per-case table from `benchmarks/evaluation_results.json` + `benchmarks/decision_behavior_corpus.py`; not part of the build, run manually if the underlying data changes |
| `README.md` | This file |

---

## arXiv Submission Notes

1. **Primary category:** `cs.CR` (Cryptography and Security)
2. **Cross-list:** `cs.AI`, `cs.LG`
3. **License:** CC BY 4.0
4. Upload `main.tex` and `references.bib` together. arXiv will compile with
   pdfLaTeX automatically.
5. The paper uses no custom style files — arXiv compilation should succeed
   without modification.
6. Set the submission title to match `\title{}` exactly.

---

## Data

Section 5 results and Appendix A (per-case table) are sourced from the
[`dgb-v1.0.0`](https://github.com/msaleme/red-team-blue-team-agent-fabric/releases/tag/dgb-v1.0.0)
release of the benchmark (see `benchmarks/CHANGELOG.md`):
- `benchmarks/evaluation_results.json` — aggregate and per-case results
- `benchmarks/decision_behavior_corpus.py` — 52-case corpus definition
- Corpus run timestamp: `2026-04-17T12:07:43Z`

The `dgb-v1.0.0` tag is versioned independently of both the paper (which
has no version number of its own until an arXiv identifier is assigned)
and the `agent-security-harness` package.

To regenerate Appendix A's LaTeX table after a corpus/results change:

```bash
python3 docs/paper-dgb/_gen_appendix.py > /tmp/appendix.tex
# paste the longtable block into main.tex's Appendix A section
```

---

## Citation

```bibtex
@misc{saleme2026dgb,
  author       = {Saleme, Michael K.},
  title        = {Decision Governance Benchmark: Executable Behavioral Tests
                  for Autonomous {AI} Agent Security},
  year         = {2026},
  howpublished = {arXiv preprint},
  note         = {Corpus and evaluation harness: dgb-v1.0.0}
}
```

To cite the corpus/harness independently of the paper (e.g. "we evaluated
against DGB v1.0.0"), see `benchmarks/README.md`'s own citation entry
instead.
