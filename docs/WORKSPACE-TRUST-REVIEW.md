# WT-001..004: what the code does, for someone deciding whether to read it

A reading guide for `protocol_tests/workspace_trust_harness.py`. It exists because a reviewer asked
for source, command semantics, fixture behaviour and provenance before deciding whether to review
this at all, and no such document existed.

**This document authorizes nothing.** It is not a request to install or execute the harness, not a
safety assessment, and not an audit. It shortens a search. Where it and the code disagree, the code
is right.

## Immutable provenance

| | |
|---|---|
| Repository | `https://github.com/msaleme/red-team-blue-team-agent-fabric` |
| Revision all citations are pinned to | `39fd4d297eda0f7be1280ef6df7d37fc4af8b054` |
| Introduced in | PR #569, merged `a6d27d6` 2026-09-10 |
| Docstring correction | `39fd4d2`, same day, after the adversarial read below |

SHA-256 of the files cited, at that revision:

```
fcd309b8f0773dbecdb8d630e161f2086142961274bf85d8f9b12be28d407a19  protocol_tests/workspace_trust_harness.py
1796dd42dd349b3421a3d704286b6f573b15cee1d9a267cc93d790bdc8878c48  testing/test_workspace_trust_controls.py
1870c10ebd481fff684a8b0635ae0b66161e1af2375d05e871b7145c3d59c38f  protocol_tests/run_provenance.py
```

Line numbers below are valid at `39fd4d2` and nowhere else. `main` moves; check out the SHA.

## Evidence class

Author-written. **E1/I0.**

A second agent read an earlier version of this document against the source and returned it with nine
findings, which are corrected below and listed at the end. **That does not make this I1.** A
different reader improves error detection; it does not make the description independent, and the
reviewer said so themselves. Nothing here should be taken from me rather than from the source.

---

## 1. It executes the command you give it, through a shell, as you

`_invoke`, **lines 176-194**:

```python
cmd = self.command.replace("{repo}", str(repo))
proc = subprocess.run(cmd, shell=True, capture_output=True,
                      text=True, timeout=120, check=False)
```

The string passed to `--command` runs with `shell=True`, in your process context, with your
privileges, inheriting this process's working directory and environment. There is no allowlist, no
parsing, no sandbox and no `cwd` or `env` isolation.

**Substitution is literal.** `{repo}` is replaced by `str(repo)` with no quoting added. The path is
a `mkdtemp` path, so it is normally well behaved, but the harness does not guarantee that and does
not escape it.

**The 120s timeout bounds this one invocation.** It does not bound processes the command spawns, and
it is not a bound on the run. §4 names a separate code path with no timeout at all.

This is the whole mechanism: the harness characterises *your* ingesting command, so it must run it.
It is the fact to decide on before anything else here.

## 2. Only WT-001 invokes that command

| Test | Lines | What it drives |
|---|---|---|
| `WT-001` | 213-232 | the command under test, via `_run_against` |
| `WT-002` | 236-270 | local `git` directly, no invocation |
| `WT-003` | 274-323 | local `git` directly, no invocation |
| `WT-004` | 327-363 | local `git` directly, no invocation |

A run therefore yields **one** observation about your command and three about git's behaviour on the
machine running the harness. The three are still useful, and none is evidence about your command.

The docstring claimed all four until `39fd4d2`. The adversarial read found it.

(The line ranges in this table were wrong in a draft of this document, off by four, written from
stale offsets. They are correct at the pinned revision, which you can confirm by opening them. That
they were derived rather than typed is my account of how, not a property the repository enforces.)

## 3. What the positive control actually establishes

WT-001 runs your command against a clean fixture first. That run is treated as "ingested" when it
**exits zero** (lines 193-195) **and writes something to stdout or stderr** (lines 196-198).

That is weaker than "the command read the repository". A command that exits zero and prints
anything, without opening the directory, satisfies it. The check exists to stop a non-ingesting
command scoring as "not vulnerable"; it does not prove ingestion.

The crafted invocation's return value is **not** checked: `_run_against` calls `self._invoke(repo)`
at **line 207** and discards what it returns. The verdict is computed from the clean control
succeeding plus whether the canary file exists (lines 200-209).

## 4. Where it works, and the one path that leaves

- `mkdtemp(prefix="wt-harness-")`, **line 147**. Fixtures live under it.
- `cleanup()`, **lines 379-380**: `shutil.rmtree(self._tmp, ignore_errors=True)`, called in a
  `finally`. `ignore_errors=True` means deletion is attempted, not verified. It says nothing about
  processes your command may have left running.
- **`--report` adds two behaviours, neither confined to the temp directory by the harness.**
  Line 428 writes to the path you pass. You choose it, so it may or may not sit outside the temp
  root; a relative path resolves against your working directory and `write_text` overwrites an
  existing file. Separately, line 418 calls `run_provenance()`, which runs git **against the harness
  checkout rather than the fixture** (`run_provenance.py`, the repo root is selected at line 687,
  the shared subprocess helper is line 191). The calls it *may* make, all without a timeout, are
  `rev-parse HEAD` (line 643, skipped when `GITHUB_SHA` is set), `describe --tags --exact-match`
  (line 654, skipped when `GITHUB_REF_NAME` is set), `status --porcelain --untracked-files=no`
  (line 656), and a `--version` probe reached only on failure (line 645). Which of them run depends
  on your environment.

If `--report` is not passed, neither happens.

## 5. What the fixture contains

`_build_repo`, **lines 158-172**. Creates a directory, writes a `README.md`, runs `git init` / `add`
/ `commit`, and only when a canary path is passed appends to the fixture's own `.git/config`:

```python
sink = f'/bin/sh -c "echo fired > {shlex.quote(str(canary))}"'
...
fh.write(f"\n[core]\n\tfsmonitor = {json.dumps(sink)}\n")
```

The sink is a real execution sink. What it executes is `echo fired > <path>`, writing one short file
inside the temp directory from §4.

**Scope of that claim:** it describes the string the harness constructs. It is not a runtime
guarantee about what executes on your machine during a run, because your command also runs (§1) and
git inherits your configuration (§6). `shlex.quote` is applied to the path, but it sits inside a
double-quoted shell string; treat it as the quoting that is there, not as a general guarantee.

## 6. Other processes, and inherited state

- `_git`, **lines 151-156**: `git` with `-c user.email` / `-c user.name` and
  `GIT_TERMINAL_PROMPT=0`, always with `cwd` inside the temp directory. Used for `init`, `add`,
  `commit`, `status`, `diff`, `log`, `config --local`.
- **Line 291**, WT-003: `git clone -q <fixture> <temp path>`, both local.

`_git` **inherits `os.environ`** (line 152) and overrides only identity and terminal prompting. It
does not isolate your git configuration or hooks. What that establishes is the absence of isolation,
not that global and system config invariably load: an inherited environment can itself alter or
suppress normal config loading.

Those are the direct subprocess calls in this file, plus §1 and the `run_provenance` path in §4.

## 7. Claims of absence, scoped honestly

The earlier version of this document said the harness makes no network calls. **That claim cannot be
made unconditionally and has been removed.** Your command runs with a shell (§1); anything it does,
including network access, is outside what this file constrains.

What is checkable:

- No direct network client is used by this module's own logic. It imports from
  `protocol_tests.http_helpers` (**line 79**) for two symbols, `INCONCLUSIVE_PREFIX` and
  `console_status`. **That module does import `urllib`** (`http_helpers.py` lines 21-23) and defines
  network helpers; this harness calls neither. An import is reach, not use, and you should confirm
  that rather than accept it.
- The `git clone` at line 291 clones a local path.

Similarly, "no modification of your repositories or environment" is **not** claimed. The `_git`
helper's calls are scoped to the temp directory, but that is not all of this module's own logic:
`run_provenance` reads the harness checkout (§4), and your command is unrestricted.

## 8. Controls

`testing/test_workspace_trust_controls.py` pins WT-001 against four target shapes defined at
**lines 51-54**, asserted at **lines 70-117**: FAIL against a naive ingester, PASS against one that
sanitises, and INCONCLUSIVE against `true` (silent, exits zero) and against `exit 3`.

Note the narrowness. Those are the two non-ingesting shapes tested. A command that produces output
without reading the directory satisfies the control (§3) and is not covered by either.

**Lines 151-203** derive from the AST which tests invoke the command and assert the set is exactly
`{WT-001}`.

CI: 8 checks including Python 3.10 through 3.13 on PR #569
(`https://github.com/msaleme/red-team-blue-team-agent-fabric/pull/569`). That run predates the
correction in `39fd4d2` and therefore does not establish that the AST guard above passed.

## 9. Statements about process, marked as unverifiable

The following are assertions by the author. Git metadata cannot establish any of them, and the
adversarial read flagged them as uncited. They are kept because withdrawing them would be less
informative than labelling them:

- Authored by Michael K. Saleme with AI assistance, in one session on 2026-09-10.
- The mechanics were reproduced against git 2.43.0 before the module was written: a directory copy
  carrying the sink fires on `git status`; the same repository obtained by `git clone` does not;
  `git -c core.fsmonitor=false status` does not. **No execution transcript was retained.**
- No external review other than the second-agent description check described above.

## 10. What this document does not establish

That running the harness is safe on your system. That depends on your command, your privileges and
your machine, none of which are visible here.

It is written by the author of the code, corrected after one second-agent read, and remains E1/I0.
It is descriptive. A completed packet authorizes neither installation nor execution.

If a reading of the source contradicts anything above, the source is correct and I would like to
know which line.

---

## Correction history

Nine correction-history entries from the second-agent read of the first version. Not a defect
count: that read covered nine sections, some carrying several observations and some, like item 2,
recording a claim that was already supported and was retained.

1. INCONCLUSIVE generalised: only the clean control is checked; the crafted return is discarded (§3)
2. Fixture confinement, correctly scoped in v1, retained
3. "does nothing else" read as a runtime guarantee, and the `shlex.quote` nesting (§5)
4. `--report`'s `run_provenance` spawns git outside the fixture root, untimed (§4)
5. `ignore_errors=True` is attempted, not verified, deletion (§4)
6. The network claim was wrong unconditionally, and `http_helpers` reaches `urllib` (§7)
7. A relative `--report` path resolves from the caller's cwd and can overwrite (§4)
8. Authorship, reproduction and "no external review" are uncited assertions (§9)
9. Only WT-001 invokes the command, a defect in the code's own docstring, fixed in `39fd4d2` (§2)
