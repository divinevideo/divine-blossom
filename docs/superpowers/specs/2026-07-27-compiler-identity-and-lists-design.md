# Compiler: Logged-In Identity Name And Own-Lists Picker

**Site:** `https://compiler.divine.video`
**Scope:** `compiler-web/` only. No backend (`cloud-run-compiler`), deployment, or config changes.
**Date:** 2026-07-27

## Problem

When a user connects their Divine identity:

1. The header shows a truncated pubkey (`d95aa8fc…5ae540`) instead of the user's Nostr profile name.
2. The user must manually paste an `naddr` or `30005:pubkey:d-tag` coordinate to open a list; their own kind-30005 lists are never discovered automatically.

## Design

### Relay (`compiler-web/src/nostr/relay.ts`)

Extend `DivineListRelay` (reuses the existing `SimplePool` and relay set):

- `profile(pubkey): Promise<ProfileMeta | null>` — `pool.get` kind 0 for the author; parse `content` JSON into `{ name?, display_name?, picture? }`. Returns `null` when no event exists or content is not valid JSON.
- `authoredLists(pubkey): Promise<NostrEvent[]>` — `querySync` kind 30005 with `authors: [pubkey]`; dedupe by `d` tag keeping the newest `created_at` (tie-break by id); sort newest first.

### Pure helpers (`compiler-web/src/nostr/lists.ts`)

Kept pure for unit testing:

- `displayNameFromProfile(meta: ProfileMeta | null): string | undefined` — `display_name || name` or `undefined`.
- `dedupeLatestLists(events: NostrEvent[]): NostrEvent[]` — d-tag dedupe + newest-first ordering used by `authoredLists`.

### App (`compiler-web/src/App.tsx`)

- After auth restore (both callback and session-restore paths), once `pubkey` is known:
  - `relay.profile(pubkey)` → store `displayName` state.
  - `relay.authoredLists(pubkey)` → store `myLists` state.
  - Both fetches are non-fatal: failures leave `displayName`/`myLists` unset and do not set `error`.
- List picker selection sets `listReference` to the list's `30005:pubkey:d-tag` coordinate and invokes the existing `loadList` flow unchanged (parse, fetch, ownership check, clip loading).
- `logout` clears `displayName` and `myLists` alongside existing state.

### Header (`compiler-web/src/components/Header.tsx`)

- New optional prop `displayName?: string`.
- When present, the identity button shows `displayName`; otherwise falls back to the current truncated pubkey rendering.

### List picker UI

- Panel rendered beneath the list-reference input, only when logged in.
- Loading state: spinner row while `authoredLists` is in flight.
- Empty state: "No lists found on relay."
- Each row: list title (`title` tag, fallback d-tag) and clip count (number of video `a` tags). Click loads the list.
- Manual input remains fully functional for opening lists by reference.

## Error Handling

- Profile fetch failure or missing kind 0 → header falls back to truncated pubkey.
- Lists fetch failure → picker hidden/empty state; no error banner (manual flow unaffected).
- Malformed kind-0 content JSON → treated as no profile.

## Testing

- `compiler-web/src/nostr/lists.test.ts`: add cases for `displayNameFromProfile` (display_name preferred, name fallback, null profile) and `dedupeLatestLists` (dedupes by d-tag, keeps newest, tie-break, ordering).
- Existing tests must keep passing: `npm --prefix compiler-web test -- --run`.
- Manual validation: connect Divine identity on the deployed/local site; header shows profile name; own lists appear in the picker; clicking one loads clips; manual naddr entry still works; logout restores the Connect button and clears name/lists.

## Out Of Scope

- Avatar rendering in the header.
- Resolving profile names for clip creators in the timeline.
- Relay configuration changes.
