# Outer VCL snippets

The service in front of `media.divine.video` is Fastly VCL
(`ML7R82HKfmTaqTpHExIDVN`), not Compute. Merging to `main` still only runs
`fastly compute publish`. Files under `vcl/` are the source for the outer
snippets; nothing else deploys them.

`vcl/snippets.json` lists the snippets this repository owns, including the
Fastly snippet name, type, and priority. `vcl/log_cdn_views.vcl` is not a live
snippet; production uses a dashboard logging endpoint. See
[CDN view counting](cdn-view-counting.md).

## Diff git against the active version

Read-only. Uses the read-only Fastly credential namespace and exits `1` when
git and the active version disagree.

```bash
envchain fastly-readonly python3 scripts/sync_outer_vcl.py diff
```

## Apply git onto a cloned draft

Clones the active version, upserts the managed snippets, validates the draft,
and prints `DRAFT_VERSION`. It never changes the live version.

```bash
envchain fastly-global python3 scripts/sync_outer_vcl.py apply
```

If every managed snippet already matches git, apply does not clone. A live
snippet absent from `vcl/snippets.json` makes apply refuse before cloning. This
keeps the active snippet set under review in git. A managed name missing on
Fastly is created only in the cloned draft and remains inert until an operator
reviews and activates that complete version.

Apply updates every snippet in the manifest, not one selected snippet. Review
the complete Fastly version diff before activation and do not activate a draft
that contains an unrelated change.

A push to `main` runs `diff` only. The same apply is available as a manual
`Outer VCL` workflow with `apply_draft`, which does not run `diff` as a
blocking prior step. Draft creation is restricted to `main` and serialized so
two workflow runs cannot update drafts concurrently. CI never makes a draft
live. A non-`main` apply dispatch fails explicitly rather than producing an
all-skipped green run.

A merge that changes a managed snippet leaves the path-scoped `diff` job red
until git and the active version agree again. Re-run the workflow after making
a matching draft live to clear that run. The log lines say what disagrees, not
which side moved: `DRIFT` is content, `MISSING_LIVE` is a managed name absent
on Fastly, `EXTRA_LIVE` is a Fastly name absent from the manifest, `META` is
type, priority, or dynamic. Use `git log -- vcl/` and the Fastly version
history to see who moved. A Fastly API error prints none of those lines.

## Add a managed snippet

Add the source file and manifest entry in a reviewed pull request. Apply creates
the missing snippet only in a cloned draft, then reads back and validates the
complete managed set. An authorized Fastly operator still reviews the full
version diff and performs activation through the normal outer-service change
procedure.

## Making a draft live

That step is an operator action, not a repository job. Follow the smoke-test,
approval, activation, and verification procedure in
[Fastly deploy and rollback](rollback.md). Do not activate from GitHub Actions.

If apply fails after printing `cloned A -> B`, treat version `B` as an abandoned
partial draft. Do not activate it; investigate the read-back failure and start
again from the then-active version.
