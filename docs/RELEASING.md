# Releasing

The order below is not stylistic. Each step exists because doing it in a
different order produced a specific, recorded failure.

## The order

```bash
# 1. Merge the release PR. The version bump lands on main in the SAME commit
#    the tag will point at -- so everything the tag should say must be IN it:
#      - pyproject.toml version bump
#      - docs/release-claims.json: rebind `release-test-count` to the NEW tag
#        (release_tag AND the `fact` sentence AND the README surface patterns)
#    testing/test_release_claims.py fails the PR if the bump lands without the
#    rebind. Do not rebind in a follow-up PR: see "Why the claim is rebound in the release PR".

# 2. Push the tag FIRST, before touching any public surface.
git tag vX.Y.Z && git push origin vX.Y.Z

# 3. Update the surfaces that name the release, and let them go live:
#      - msaleme/start-here          README (includes a copyable Action pin)
#      - https://pubpoint.com/facts-evidence/   (Cloudflare Pages; wait for deploy)
#    The exact figures to write:
python3 scripts/check_public_metadata.py --print-expected

# 4. Gate. This must print OK (preflight) before you go on.
python3 scripts/check_public_metadata.py --preflight

# 5. Publish. --verify-tag refuses to invent a tag that does not exist.
gh release create vX.Y.Z --verify-tag --title "..." --notes-file ...
```

`--apply` (step 3, optional) rewrites the repository **description** to the
tree's figures. It cannot touch anything in step 3's list: those live in other
repositories.

## Why the claim is rebound in the release PR

`docs/release-claims.json` binds each release-facing fact to the revision, command and
value that produced it. Until 2026-09-10 it was rebound in a PR that landed *after* the
tag, which meant the tree every tag pointed at named the release **before** it:

    v4.21.0   pyproject 4.21.0   manifest v4.20.0   (and the previous value, 611)
    v4.21.1   pyproject 4.21.1   manifest v4.21.0
    v4.21.2   pyproject 4.21.2   manifest v4.21.1
    v4.21.3   pyproject 4.21.3   manifest v4.21.2

Four for four. `main` reconciled minutes later, so every check that runs on `main` saw an
agreeing pair and nothing flagged it.

It is not cosmetic, and it propagates outward. An external nightly sentinel pinned at
`v4.21.3` was sent *by this manifest* to regenerate a value at `v4.21.2` -- a tag its
`--depth 1 --branch v4.21.3` clone could not contain -- and correctly reported the check
as not reproduced. A manifest bound one release back turns a shallow clone from
sufficient into insufficient.

`testing/test_release_claims.py::test_a_release_claim_names_the_version_the_tree_is_at`
asserts `release_tag == "v" + <pyproject version>`. It compares against `pyproject.toml`
rather than `git tag` on purpose: no tag object is needed, so it holds in the depth-1
clone CI uses, and it fires in the release commit itself -- the one moment the version
has moved and the manifest has not. On every other commit the two agree and it is silent.

## Why the tag goes before the surfaces

`start-here` carries a copyable GitHub Action pin:

    uses: msaleme/red-team-blue-team-agent-fabric@vX.Y.Z

If the surfaces are updated before the tag is pushed, that pin names a tag that
does not exist, and anyone who copies it during the window gets a workflow that
cannot resolve. **A pin that 404s is worse than a pin that is one version behind
and works.** Pushing the tag first (step 2) closes that window: the pin resolves
from the moment it is published.

## Why the release object goes last

`Public metadata drift` runs on `release: published`. It compares the tree at the
highest release tag against the surfaces **read live at that moment**. Publish
the release before the surfaces are current and it fails — correctly, and every
time.

That is not hypothetical. It happened on four consecutive releases for the
description (v4.18.0, v4.19.0rc1, v4.19.0, v4.20.0), was fixed for the
description by `--apply`, and then recurred on four more (v4.21.0, v4.21.1,
v4.21.2, v4.21.3) through the two remote surfaces `--apply` cannot reach.

Publishing last means the workflow's first run is against a world that already
agrees.

## A failed release run is not permanently red

Both sides of that comparison are read at run time — the tag list and the live
surfaces — so a run that failed because a surface was stale **passes on re-run
once the surface is fixed**:

```bash
gh run rerun <run-id> -R msaleme/red-team-blue-team-agent-fabric
```

Verified 2026-09-09: re-running turned v4.21.0 through v4.21.3 green with no
change to those tags. Do not re-cut a tag to clear this.

(This differs from a workflow-file fix, which genuinely cannot reach an existing
tag, because the workflow file *is* read from the tag's commit.)

## What `--preflight` is for, and what it refuses

Between steps 2 and 4 the tag exists but the release object does not, so the
release-date lookup 404s and an ordinary run exits `2` (UNREACHABLE) however
correct the surfaces are. A gate that can never return `0` is not a gate.

`--preflight` treats that one 404 as expected and prints what it skipped:

```
OK (preflight)  ... match the tree (... , vX.Y.Z)
    Release date NOT checked: vX.Y.Z is not published yet.
    Re-run without --preflight after `gh release create`.
```

It is **refused once the release exists** — exit `1`, telling you to re-run
without it. Otherwise the flag would be a way to skip a check that could have
run, which is the defect this checker exists to catch, wearing a flag.

It excuses nothing else. A 403, a rate limit, a network error, a stale count or
a stale version all still fail under `--preflight`. See
`testing/test_public_metadata_check.py::TestPreflight`.

## Exit codes

| code | meaning |
|------|---------|
| `0` | every surface agrees with the tree |
| `1` | drift — the surfaces are named individually |
| `2` | UNREACHABLE — a surface was not read. **Not a pass.** |
