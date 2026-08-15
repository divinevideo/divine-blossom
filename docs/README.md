# Blossom Documentation Map

This directory is the index for repository documentation. Current docs first, historical context second.

## Current

- [README.md](../README.md) — service overview, setup, architecture
- [CLAUDE.md](../CLAUDE.md) — working notes for AI-assisted development
- [OAUTH_SETUP.md](../OAUTH_SETUP.md) — OAuth configuration for admin UI
- [CHANGELOG.md](../CHANGELOG.md) — release history
- [docs/api/](api/) — cross-service API contracts (creator-delete, etc.)
- [docs/runbooks/](runbooks/) — operational runbooks, including deployment, CDN view counting, and edge upload observability
- [docs/cdn-evaluation-status.md](cdn-evaluation-status.md) — **start here** for the CDN and delivery-origin evaluation: current state, results, open questions
- [docs/cdn-object-storage-vendor-notes.md](cdn-object-storage-vendor-notes.md) — CDN and object-storage vendor capability notes
- [docs/measurements/](measurements/) — synthetic CDN and delivery measurements
- [docs/derivative-status-queue.md](derivative-status-queue.md) — Cloud Tasks rollout notes for derivative status callbacks

## Historical

- [docs/superpowers/](superpowers/README.md) — per-PR planning and design artifacts, preserved for context

## Source-of-truth rule

When docs and code disagree, trust the code. Historical docs describe intent at a point in time and are not maintained after the linked PR ships.
