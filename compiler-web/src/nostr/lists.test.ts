import { describe, expect, it, vi } from 'vitest'
import type { NostrEvent, NostrSigner } from '../types'
import {
  assertCurrentEditBase,
  buildReorderedListEvent,
  dedupeLatestLists,
  coordinateFilters,
  displayNameFromProfile,
  newestByCoordinate,
  profileNamesByPubkey,
  saveReorderedList,
  videoReferences,
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
      'same video references',
    )
    expect(() =>
      buildReorderedListEvent(baseEvent, [coordinateA, coordinateA], 200),
    ).toThrow('same video references')
    expect(() =>
      buildReorderedListEvent(baseEvent, [coordinateA, `34236:${pubkey}:foreign`], 200),
    ).toThrow('same video references')
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
    expect(videoReferences(baseEvent)).toEqual([coordinateA, coordinateB])
  })
})

describe('app authored lists that reference clips by event id', () => {
  const eventIdA = '1'.repeat(64)
  const eventIdB = '2'.repeat(64)
  const appList: NostrEvent = {
    ...baseEvent,
    tags: [
      ['d', 'list_1785619462240'],
      ['title', 'Halloween square Divine'],
      ['play-order', 'chronological'],
      ['e', eventIdA],
      ['e', eventIdB],
      ['e', 'not-an-event-id'],
      ['p', 'f'.repeat(64)],
    ],
  }

  it('reads ordered e tags and ignores malformed ones', () => {
    expect(videoReferences(appList)).toEqual([eventIdA, eventIdB])
  })

  it('reorders e tag slots and leaves other tags in place', () => {
    const result = buildReorderedListEvent(appList, [eventIdB, eventIdA], 300)

    expect(result.tags).toEqual([
      ['d', 'list_1785619462240'],
      ['title', 'Halloween square Divine'],
      ['play-order', 'manual'],
      ['e', eventIdB],
      ['e', eventIdA],
      ['e', 'not-an-event-id'],
      ['p', 'f'.repeat(64)],
    ])
  })

  it('reorders lists that mix event ids and coordinates', () => {
    const mixed: NostrEvent = {
      ...baseEvent,
      tags: [
        ['d', 'mixed'],
        ['e', eventIdA],
        ['a', coordinateA],
      ],
    }

    const result = buildReorderedListEvent(mixed, [coordinateA, eventIdA], 300)

    expect(result.tags).toEqual([
      ['d', 'mixed'],
      ['play-order', 'manual'],
      ['a', coordinateA],
      ['e', eventIdA],
    ])
  })
})

describe('displayNameFromProfile', () => {
  it('prefers display_name over name', () => {
    expect(
      displayNameFromProfile({ name: 'alice', display_name: 'Alice A.' }),
    ).toBe('Alice A.')
  })

  it('falls back to name when display_name is missing', () => {
    expect(displayNameFromProfile({ name: 'alice' })).toBe('alice')
  })

  it('returns undefined for null or empty profiles', () => {
    expect(displayNameFromProfile(null)).toBeUndefined()
    expect(displayNameFromProfile({})).toBeUndefined()
  })
})

describe('dedupeLatestLists', () => {
  const list = (id: string, dTag: string, createdAt: number): NostrEvent => ({
    id,
    pubkey,
    created_at: createdAt,
    kind: 30005,
    tags: [['d', dTag]],
    content: '',
    sig: 'e'.repeat(128),
  })

  it('keeps only the newest event per d tag', () => {
    const stale = list('1'.repeat(64), 'picks', 100)
    const fresh = list('2'.repeat(64), 'picks', 200)

    expect(dedupeLatestLists([stale, fresh])).toEqual([fresh])
    expect(dedupeLatestLists([fresh, stale])).toEqual([fresh])
  })

  it('breaks created_at ties by id descending', () => {
    const lower = list('a'.repeat(64), 'picks', 100)
    const higher = list('b'.repeat(64), 'picks', 100)

    expect(dedupeLatestLists([lower, higher])).toEqual([higher])
  })

  it('sorts distinct lists newest first', () => {
    const old = list('1'.repeat(64), 'old', 100)
    const mid = list('2'.repeat(64), 'mid', 200)
    const fresh = list('3'.repeat(64), 'fresh', 300)

    expect(dedupeLatestLists([mid, old, fresh])).toEqual([fresh, mid, old])
  })

  it('treats events without a d tag as distinct entries', () => {
    const noTagA = { ...list('1'.repeat(64), 'x', 100), tags: [] }
    const noTagB = { ...list('2'.repeat(64), 'y', 200), tags: [] }

    expect(dedupeLatestLists([noTagA, noTagB])).toHaveLength(2)
  })
})

describe('profileNamesByPubkey', () => {
  const author = '9'.repeat(64)
  const profile = (id: string, createdAt: number, content: string): NostrEvent => ({
    id,
    pubkey: author,
    created_at: createdAt,
    kind: 0,
    tags: [],
    content,
    sig: 'e'.repeat(128),
  })

  it('keeps the newest profile per pubkey', () => {
    const stale = profile('1'.repeat(64), 100, '{"name":"old"}')
    const fresh = profile('2'.repeat(64), 200, '{"display_name":"Fresh Name"}')

    expect(profileNamesByPubkey([fresh, stale]).get(author)).toBe('Fresh Name')
    expect(profileNamesByPubkey([stale, fresh]).get(author)).toBe('Fresh Name')
  })

  it('falls back to name and skips unusable profiles', () => {
    expect(profileNamesByPubkey([profile('3'.repeat(64), 1, '{"name":"handle"}')]).get(author))
      .toBe('handle')
    expect(profileNamesByPubkey([profile('4'.repeat(64), 1, 'not json')]).size).toBe(0)
    expect(profileNamesByPubkey([profile('5'.repeat(64), 1, '{}')]).size).toBe(0)
  })

  it('ignores non profile events', () => {
    const note: NostrEvent = {
      id: '6'.repeat(64),
      pubkey: author,
      created_at: 1,
      kind: 1,
      tags: [],
      content: '{"name":"nope"}',
      sig: 'e'.repeat(128),
    }
    expect(profileNamesByPubkey([note]).size).toBe(0)
  })
})

describe('coordinateFilters', () => {
  const authorA = '7'.repeat(64)
  const authorB = '8'.repeat(64)

  it('groups identifiers by author and kind instead of one filter per clip', () => {
    const filters = coordinateFilters([
      `34236:${authorA}:one`,
      `34236:${authorA}:two`,
      `34235:${authorA}:three`,
      `34236:${authorB}:four`,
      `34236:${authorA}:one`,
    ])

    expect(filters).toHaveLength(3)
    expect(filters).toContainEqual({
      kinds: [34236],
      authors: [authorA],
      '#d': ['one', 'two'],
    })
    expect(filters).toContainEqual({ kinds: [34235], authors: [authorA], '#d': ['three'] })
    expect(filters).toContainEqual({ kinds: [34236], authors: [authorB], '#d': ['four'] })
  })

  it('chunks large author groups and skips malformed coordinates', () => {
    const many = Array.from({ length: 250 }, (_, index) => `34236:${authorA}:clip-${index}`)
    const filters = coordinateFilters([...many, 'not-a-coordinate', `34236:${authorA}:`])

    expect(filters).toHaveLength(3)
    expect(filters.map((filter) => filter['#d'].length)).toEqual([100, 100, 50])
  })
})

describe('newestByCoordinate', () => {
  const author = '6'.repeat(64)
  const video = (id: string, createdAt: number, identifier: string): NostrEvent => ({
    id,
    pubkey: author,
    created_at: createdAt,
    kind: 34236,
    tags: [['d', identifier]],
    content: '',
    sig: 'e'.repeat(128),
  })

  it('keeps the newest event per coordinate', () => {
    const stale = video('1'.repeat(64), 100, 'clip')
    const fresh = video('2'.repeat(64), 200, 'clip')
    const other = video('3'.repeat(64), 100, 'another')

    const newest = newestByCoordinate([fresh, stale, other])

    expect(newest.get(`34236:${author}:clip`)).toEqual(fresh)
    expect(newest.get(`34236:${author}:another`)).toEqual(other)
  })
})
