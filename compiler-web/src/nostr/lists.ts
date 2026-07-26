import type {
  NostrEvent,
  NostrSigner,
  NostrTag,
  UnsignedNostrEvent,
} from '../types'
import type { ListRelay } from './relay'

const VIDEO_KINDS = new Set([34235, 34236])

export function videoCoordinates(event: NostrEvent): string[] {
  return event.tags
    .filter(isVideoTag)
    .map((tag) => tag[1])
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
  orderedCoordinates: string[],
  createdAt: number,
): UnsignedNostrEvent {
  if (base.kind !== 30005) {
    throw new Error('Only kind 30005 video lists can be edited.')
  }
  listIdentifier(base)
  const currentCoordinates = videoCoordinates(base)
  if (!sameUniqueValues(currentCoordinates, orderedCoordinates)) {
    throw new Error('The replacement must contain the same video coordinates exactly once.')
  }

  const tagByCoordinate = new Map<string, NostrTag>()
  for (const tag of base.tags) {
    if (isVideoTag(tag)) {
      tagByCoordinate.set(tag[1], tag)
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
      const coordinate = orderedCoordinates[videoIndex]
      const originalTag = tagByCoordinate.get(coordinate)
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
  orderedCoordinates: string[],
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

  const unsigned = buildReorderedListEvent(base, orderedCoordinates, createdAt)
  const signed = await signer.signEvent(unsigned)
  if (signed.pubkey !== base.pubkey || signed.kind !== 30005) {
    throw new Error('The signer returned the wrong list identity.')
  }
  await relay.publish(signed)
  return signed
}

function isVideoTag(tag: NostrTag): boolean {
  if (tag[0] !== 'a' || typeof tag[1] !== 'string') {
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
  return [...currentSet].every((coordinate) => replacementSet.has(coordinate))
}
