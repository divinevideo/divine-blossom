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

Read-only. Needs `FASTLY_API_TOKEN` in the environment. Exits `1` when git and
the active version disagree.

```bash
python3 scripts/sync_outer_vcl.py diff
```

## Apply git onto a cloned draft

Clones the active version, upserts the managed snippets, validates the draft,
and prints `DRAFT_VERSION`. The live version does not change.

```bash
python3 scripts/sync_outer_vcl.py apply
```

If the active version already matches git, apply does not clone. If Fastly has
a snippet that is not in `vcl/snippets.json`, apply refuses rather than
deleting it. Apply reconciles every snippet in the manifest, not one selected
snippet. Review the complete Fastly version diff before activation and do not
activate a draft that contains an unrelated change.

A push to `main` runs `diff` only. The same apply is available as a manual
`Outer VCL` workflow with `apply_draft`, which does not run `diff` as a
blocking prior step. Draft creation is restricted to `main` and serialized so
two workflow runs cannot update drafts concurrently. CI never makes a draft
live.

A merge that changes a managed snippet leaves the path-scoped `diff` job red
until git and the active version agree again. Re-run the workflow after making
a matching draft live to clear that run. The log lines say what disagrees, not
which side moved: `DRIFT` is content, `MISSING_LIVE` is a managed name absent
on Fastly, `EXTRA_LIVE` is a Fastly name absent from the manifest, `META` is
type, priority, or dynamic. Use `git log -- vcl/` and the Fastly version
history to see who moved. A Fastly API error prints none of those lines.

## Making a draft live

That step is an operator action, not a repository job. Follow the smoke-test and
approval gates in [Fastly deploy and rollback](rollback.md), review the complete
Fastly version diff, then:

```bash
fastly service-version activate --service-id ML7R82HKfmTaqTpHExIDVN --version <DRAFT_VERSION>
```

Do not run that from GitHub Actions.
