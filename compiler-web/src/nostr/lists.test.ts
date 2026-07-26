import { describe, expect, it, vi } from 'vitest'
import type { NostrEvent, NostrSigner } from '../types'
import {
  assertCurrentEditBase,
  buildReorderedListEvent,
  saveReorderedList,
  videoCoordinates,
} from './lists'
import type { ListRelay } from './relay'

const pubkey = 'a'.repeat(64)
const coordinateA = `34236:${'b'.repeat(64)}:first`
const coordinateB = `34235:${'c'.repeat(64)}:second`

const baseEvent: NostrEvent = {
  id: 'd'.repeat(64),
  pubkey,
  created_at: 100,
  kind: 30005,
  tags: [
    ['d', 'staff-picks'],
    ['unknown', 'preserve', 'all', 'values'],
    ['play-order', 'old'],
    ['a', coordinateA, 'wss://relay.divine.video'],
    ['title', 'Staff picks'],
    ['a', coordinateB],
    ['play-order', 'duplicate'],
  ],
  content: 'Keep this exact content',
  sig: 'e'.repeat(128),
}

describe('ordered list replacement', () => {
  it('reorders only video slots and canonicalizes manual play order', () => {
    const result = buildReorderedListEvent(baseEvent, [coordinateB, coordinateA], 200)

    expect(result.content).toBe(baseEvent.content)
    expect(result.tags).toEqual([
      ['d', 'staff-picks'],
      ['unknown', 'preserve', 'all', 'values'],
      ['play-order', 'manual'],
      ['a', coordinateB],
      ['title', 'Staff picks'],
      ['a', coordinateA, 'wss://relay.divine.video'],
    ])
    expect(result.created_at).toBe(200)
  })

  it('inserts manual play order immediately before the first video slot', () => {
    const withoutPlayOrder = {
      ...baseEvent,
      tags: baseEvent.tags.filter((tag) => tag[0] !== 'play-order'),
    }

    const result = buildReorderedListEvent(
      withoutPlayOrder,
      [coordinateA, coordinateB],
      200,
    )

    expect(result.tags[2]).toEqual(['play-order', 'manual'])
    expect(result.tags[3]).toBe(withoutPlayOrder.tags[2])
  })

  it('rejects missing, duplicate, or foreign coordinates', () => {
    expect(() => buildReorderedListEvent(baseEvent, [coordinateA], 200)).toThrow(
      'same video coordinates',
    )
    expect(() =>
      buildReorderedListEvent(baseEvent, [coordinateA, coordinateA], 200),
    ).toThrow('same video coordinates')
    expect(() =>
      buildReorderedListEvent(baseEvent, [coordinateA, `34236:${pubkey}:foreign`], 200),
    ).toThrow('same video coordinates')
  })

  it('rejects a stale edit base using full event IDs', () => {
    expect(() => assertCurrentEditBase(baseEvent.id, 'f'.repeat(64))).toThrow(
      'This list changed. Reload it before saving.',
    )
  })

  it('saves only after latest-event conflict check and relay acknowledgement', async () => {
    const signed = {
      ...baseEvent,
      id: '1'.repeat(64),
      created_at: 200,
      tags: buildReorderedListEvent(baseEvent, [coordinateB, coordinateA], 200).tags,
    }
    const relay: ListRelay = {
      latestList: vi.fn().mockResolvedValue(baseEvent),
      publish: vi.fn().mockResolvedValue(undefined),
    }
    const signer: NostrSigner = {
      getPublicKey: vi.fn().mockResolvedValue(pubkey),
      signEvent: vi.fn().mockResolvedValue(signed),
    }

    await expect(
      saveReorderedList(relay, signer, baseEvent, [coordinateB, coordinateA], 200),
    ).resolves.toEqual(signed)
    expect(relay.publish).toHaveBeenCalledWith(signed)
  })

  it('extracts only literal supported video coordinates', () => {
    expect(videoCoordinates(baseEvent)).toEqual([coordinateA, coordinateB])
  })
})
