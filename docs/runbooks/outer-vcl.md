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
deleting it.

A push to `main` runs `diff` only. The same apply is available as a manual
`Outer VCL` workflow with `apply_draft`, which does not run `diff` as a
blocking prior step. CI never makes a draft live.

## Making a draft live

That step is an operator action, not a repository job. Review the Fastly version
diff, then:

```bash
fastly service-version activate --service-id ML7R82HKfmTaqTpHExIDVN --version <DRAFT_VERSION>
```

Do not run that from GitHub Actions.
