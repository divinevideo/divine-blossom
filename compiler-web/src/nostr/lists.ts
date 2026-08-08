import type {
  NostrEvent,
  NostrSigner,
  NostrTag,
  UnsignedNostrEvent,
} from '../types'
import type { ListRelay } from './relay'

const VIDEO_KINDS = new Set([34235, 34236])

export interface ProfileMeta {
  name?: string
  display_name?: string
  picture?: string
}

export function displayNameFromProfile(meta: ProfileMeta | null): string | undefined {
  return meta?.display_name || meta?.name || undefined
}

/**
 * Latest kind 0 profile per author, parsed into display metadata. Relays may
 * return several kind 0 events for one pubkey; the newest wins.
 */
export function profileNamesByPubkey(events: NostrEvent[]): Map<string, string> {
  const latest = new Map<string, NostrEvent>()
  for (const event of events) {
    if (event.kind !== 0) continue
    const current = latest.get(event.pubkey)
    if (
      !current ||
      event.created_at > current.created_at ||
      (event.created_at === current.created_at && event.id.localeCompare(current.id) > 0)
    ) {
      latest.set(event.pubkey, event)
    }
  }

  const names = new Map<string, string>()
  for (const [pubkey, event] of latest) {
    const name = displayNameFromProfile(parseProfile(event.content))
    if (name) names.set(pubkey, name)
  }
  return names
}

function parseProfile(content: string): ProfileMeta | null {
  try {
    const meta: unknown = JSON.parse(content)
    if (typeof meta !== 'object' || meta === null) return null
    return meta as ProfileMeta
  } catch {
    return null
  }
}

export function dedupeLatestLists(events: NostrEvent[]): NostrEvent[] {
  const latestByIdentifier = new Map<string, NostrEvent>()
  const noIdentifier: NostrEvent[] = []
  for (const event of events) {
    const identifier = event.tags.find(
      (tag) => tag[0] === 'd' && typeof tag[1] === 'string' && tag[1].length > 0,
    )?.[1]
    if (!identifier) {
      noIdentifier.push(event)
      continue
    }
    const current = latestByIdentifier.get(identifier)
    if (
      !current ||
      event.created_at - current.created_at > 0 ||
      (event.created_at === current.created_at && event.id.localeCompare(current.id) > 0)
    ) {
      latestByIdentifier.set(identifier, event)
    }
  }
  return [...latestByIdentifier.values(), ...noIdentifier].sort(
    (left, right) =>
      right.created_at - left.created_at || right.id.localeCompare(left.id),
  )
}

/**
 * Ordered clip references in a signed list. The Divine app writes `e` tags
 * holding video event ids; the compiler editor writes `a` tags holding
 * addressable coordinates. Both are honoured, in literal tag order.
 */
export function videoReferences(event: NostrEvent): string[] {
  return event.tags
    .filter(isVideoTag)
    .map((tag) => tag[1])
}

/** Relays cap filter array sizes, so every batched lookup is chunked. */
export const RELAY_FILTER_CHUNK = 100

export function chunked<T>(values: T[], size = RELAY_FILTER_CHUNK): T[][] {
  const chunks: T[][] = []
  for (let index = 0; index < values.length; index += size) {
    chunks.push(values.slice(index, index + size))
  }
  return chunks
}

/**
 * Addressable lookups grouped by kind and author, so a 64-clip list is a
 * handful of filters rather than 64 concurrent subscriptions.
 */
export function coordinateFilters(
  coordinates: string[],
): { kinds: number[]; authors: string[]; '#d': string[] }[] {
  const byAuthorKind = new Map<string, Set<string>>()
  for (const coordinate of new Set(coordinates)) {
    const [kindText, pubkey, ...identifierParts] = coordinate.split(':')
    const identifier = identifierParts.join(':')
    if (!kindText || !pubkey || !identifier) continue
    const key = `${Number(kindText)}:${pubkey}`
    const identifiers = byAuthorKind.get(key) ?? new Set<string>()
    identifiers.add(identifier)
    byAuthorKind.set(key, identifiers)
  }

  const filters: { kinds: number[]; authors: string[]; '#d': string[] }[] = []
  for (const [key, identifiers] of byAuthorKind) {
    const [kindText, pubkey] = key.split(':')
    for (const chunk of chunked([...identifiers])) {
      filters.push({ kinds: [Number(kindText)], authors: [pubkey], '#d': chunk })
    }
  }
  return filters
}

/** Newest replaceable event per `kind:pubkey:d` coordinate. */
export function newestByCoordinate(events: NostrEvent[]): Map<string, NostrEvent> {
  const newest = new Map<string, NostrEvent>()
  for (const event of events) {
    const identifier = event.tags.find(
      (tag) => tag[0] === 'd' && typeof tag[1] === 'string' && tag[1].length > 0,
    )?.[1]
    if (!identifier) continue
    const coordinate = `${event.kind}:${event.pubkey}:${identifier}`
    const current = newest.get(coordinate)
    if (
      !current ||
      event.created_at > current.created_at ||
      (event.created_at === current.created_at && event.id.localeCompare(current.id) > 0)
    ) {
      newest.set(coordinate, event)
    }
  }
  return newest
}

export function isEventReference(reference: string): boolean {
  return /^[0-9a-f]{64}$/.test(reference)
}

export function listIdentifier(event: NostrEvent): string {
  const identifier = event.tags.find(
    (tag) => tag[0] === 'd' && typeof tag[1] === 'string' && tag[1].length > 0,
  )?.[1]
  if (!identifier) {
    throw new Error('The list has no non-empty d tag.')
  }
  return identifier
}

export function buildReorderedListEvent(
  base: NostrEvent,
  orderedReferences: string[],
  createdAt: number,
): UnsignedNostrEvent {
  if (base.kind !== 30005) {
    throw new Error('Only kind 30005 video lists can be edited.')
  }
  listIdentifier(base)
  const currentReferences = videoReferences(base)
  if (!sameUniqueValues(currentReferences, orderedReferences)) {
    throw new Error('The replacement must contain the same video references exactly once.')
  }

  const tagByReference = new Map<string, NostrTag>()
  for (const tag of base.tags) {
    if (isVideoTag(tag)) {
      tagByReference.set(tag[1], tag)
    }
  }

  let videoIndex = 0
  let keptPlayOrder = false
  const tags: NostrTag[] = []
  for (const tag of base.tags) {
    if (tag[0] === 'play-order') {
      if (!keptPlayOrder) {
        tags.push(['play-order', 'manual'])
        keptPlayOrder = true
      }
      continue
    }
    if (isVideoTag(tag)) {
      if (!keptPlayOrder) {
        tags.push(['play-order', 'manual'])
        keptPlayOrder = true
      }
      const reference = orderedReferences[videoIndex]
      const originalTag = tagByReference.get(reference)
      if (!originalTag) {
        throw new Error('A reordered video tag disappeared.')
      }
      tags.push(originalTag)
      videoIndex += 1
      continue
    }
    tags.push(tag)
  }

  return {
    pubkey: base.pubkey,
    kind: 30005,
    created_at: Math.max(createdAt, base.created_at + 1),
    tags,
    content: base.content,
  }
}

export function assertCurrentEditBase(baseId: string, latestId: string): void {
  if (baseId !== latestId) {
    throw new Error('This list changed. Reload it before saving.')
  }
}

export async function saveReorderedList(
  relay: ListRelay,
  signer: NostrSigner,
  base: NostrEvent,
  orderedReferences: string[],
  createdAt = Math.floor(Date.now() / 1000),
): Promise<NostrEvent> {
  const signerPubkey = await signer.getPublicKey()
  if (signerPubkey !== base.pubkey) {
    throw new Error('The connected signer does not own this list.')
  }
  const latest = await relay.latestList(base.pubkey, listIdentifier(base))
  if (!latest) {
    throw new Error('The current list could not be found on the relay.')
  }
  assertCurrentEditBase(base.id, latest.id)

  const unsigned = buildReorderedListEvent(base, orderedReferences, createdAt)
  const signed = await signer.signEvent(unsigned)
  if (signed.pubkey !== base.pubkey || signed.kind !== 30005) {
    throw new Error('The signer returned the wrong list identity.')
  }
  await relay.publish(signed)
  return signed
}

function isVideoTag(tag: NostrTag): boolean {
  if (typeof tag[1] !== 'string') {
    return false
  }
  if (tag[0] === 'e') {
    return isEventReference(tag[1])
  }
  if (tag[0] !== 'a') {
    return false
  }
  const [kindText, pubkey, identifier] = tag[1].split(':', 3)
  const kind = Number(kindText)
  return (
    VIDEO_KINDS.has(kind) &&
    /^[0-9a-f]{64}$/.test(pubkey ?? '') &&
    (identifier?.length ?? 0) > 0
  )
}

function sameUniqueValues(current: string[], replacement: string[]): boolean {
  if (current.length !== replacement.length) {
    return false
  }
  const currentSet = new Set(current)
  const replacementSet = new Set(replacement)
  if (
    currentSet.size !== current.length ||
    replacementSet.size !== replacement.length ||
    currentSet.size !== replacementSet.size
  ) {
    return false
  }
  return [...currentSet].every((reference) => replacementSet.has(reference))
}
