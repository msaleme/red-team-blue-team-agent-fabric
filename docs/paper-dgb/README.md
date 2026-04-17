# Decision Governance Benchmark — arXiv Paper

LaTeX source for: *Decision Governance Benchmark: Executable Behavioral Tests
for Autonomous AI Agent Security* (Saleme 2026).

**Targets:** arXiv CS.CR (primary) | NeurIPS 2026 Evaluations & Datasets (stretch, deadline May 6 2026)

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

All packages are included in TeX Live (full) and MikTeX. No custom `.sty`
files are required — the paper uses the standard `article` class with
`[10pt,twocolumn]` options, which is the standard arXiv CS submission format.

---

## File List

| File | Description |
|------|-------------|
| `main.tex` | Full paper source |
| `references.bib` | BibTeX bibliography (15 entries) |
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

Section 5 results are sourced from:
- `benchmarks/evaluation_results.json` — aggregate and per-case results
- `benchmarks/decision_behavior_corpus.py` — 52-case corpus definition
- Corpus run timestamp: `2026-04-17T12:07:43Z`

---

## Citation

```bibtex
@misc{saleme2026dgb,
  author       = {Saleme, Michael K.},
  title        = {Decision Governance Benchmark: Executable Behavioral Tests
                  for Autonomous {AI} Agent Security},
  year         = {2026},
  howpublished = {arXiv preprint},
  note         = {NeurIPS 2026 Evaluations \& Datasets track submission}
}
```
