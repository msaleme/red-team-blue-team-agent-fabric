# WT-001..004: what the code does, for someone deciding whether to run it

This is a reading guide for `protocol_tests/workspace_trust_harness.py`. It exists because running
this harness means letting it execute a command on your machine, and you should decide that from the
source rather than from a description of it.

**Every claim below cites a line range. Open them.** The point of this document is to shorten your
search, not to replace it. Where a claim and the code disagree, the code is right and this document
is wrong.

All line numbers are at `a6d27d6` (PR #569, merged 2026-09-10).

---

## 1. It executes the command you give it, through a shell

`_invoke`, **lines 145-163**:

```python
cmd = self.command.replace("{repo}", str(repo))
proc = subprocess.run(cmd, shell=True, capture_output=True,
                      text=True, timeout=120, check=False)
```

The string you pass to `--command` is run with `shell=True`, after `{repo}` is replaced with a path
to a fixture repository the harness built. There is no allowlist, no parsing, and no sandbox. If you
pass a command, that command runs, with your privileges, in your environment.

This is the whole mechanism of the harness: it characterises *your* ingesting command, so it has to
run it. It is also the fact worth deciding on before anything else in this document.

Timeout is 120s. A non-zero exit or empty output is treated as "did not ingest" and produces
INCONCLUSIVE rather than a verdict.

## 2. Where it works

**Line 116**: `self._tmp = Path(tempfile.mkdtemp(prefix="wt-harness-"))`

Every fixture repository it builds lives under that one directory.

## 3. What the fixture contains

`_build_repo`, **lines 127-143**. For each fixture it creates a directory, writes a `README.md`,
runs `git init` / `add` / `commit`, and then, only when a canary path is passed, appends this to the
fixture's own `.git/config`:

```python
sink = f'/bin/sh -c "echo fired > {shlex.quote(str(canary))}"'
...
fh.write(f"\n[core]\n\tfsmonitor = {json.dumps(sink)}\n")
```

So the sink is a real execution sink, and what it executes is `echo fired > <path>` where `<path>`
is a file inside the temp directory from line 116. It writes one short file and does nothing else.
`shlex.quote` is applied to the path.

This is the payload. If you are going to check one thing in this document against the source, check
this line.

## 4. Every other process it starts

- `_git`, **lines 120-125**: `git` with `-c user.email` / `-c user.name` set and
  `GIT_TERMINAL_PROMPT=0`, always with `cwd` inside the temp directory. Used for `init`, `add`,
  `commit`, `status`, `diff`, `log`, and `config --local`.
- **Line 256**, in WT-003: `git clone -q <fixture> <temp path>`, both inside the temp directory.

Those are the only subprocess calls besides §1. There are no others in the file.

## 5. What it deletes

`cleanup()`, **lines 344-345**: `shutil.rmtree(self._tmp, ignore_errors=True)`, scoped to the
directory from line 116. `main()` calls it in a `finally`.

## 6. Claims of absence, and how to check them

Each of these is checkable from the source; none should be taken on my word.

- **No network.** There are no imports of `urllib`, `socket`, `http`, or `requests` in the file, and
  no subprocess call reaches the network. `git clone` at line 256 clones a local path. Verify by
  grepping the imports at the top of the file.
- **No modification of your repositories, git config, or environment.** Every `_git` call passes
  `cwd` inside the temp directory and sets identity via `-c` flags rather than writing config. There
  is no `--global`, no `git config --system`, and no write to any path outside line 116's directory,
  **with one exception in §7.**

## 7. The one write outside the temp directory

**Line 393**, in `main()`:

```python
Path(args.report).write_text(json.dumps(report, indent=2, default=str), ...)
```

`--report` writes to whatever path you give it. That is the intended behaviour and it is the only
filesystem write the harness performs outside its own temp directory. It happens only if you pass
the flag.

Stating it because "writes nothing outside the temp directory" would otherwise be a convenient and
false summary.

## 8. Provenance

- Introduced in **PR #569**, merged as **`a6d27d6`** on 2026-09-10.
- Authored by Michael K. Saleme with AI assistance, in a single session on 2026-09-10.
- CI at merge: 8 checks, including tests on Python 3.10 through 3.13.
- Controls: `testing/test_workspace_trust_controls.py`, which pins WT-001 to FAIL against a naive
  ingester, PASS against a sanitising one, and INCONCLUSIVE against a command that ingests nothing.
- The mechanics it relies on were reproduced against git 2.43.0 before the module was written:
  a directory copy carrying the sink fires on `git status`; the same repository obtained by
  `git clone` does not; `git -c core.fsmonitor=false status` does not.

It has had no external review. This document is the first thing written for an outside reader.

## 9. What this document does not establish

It does not establish that running the harness is safe on your system. That depends on what your
command does, what privileges it holds, and what else is on the machine, and none of those are
visible from here.

It is written by the author of the code. It is not an audit, not independent, and not a security
assessment. It says what the code does and points at where to confirm it.

If a reading of the source contradicts anything above, the source is correct and I would like to
know which line.
