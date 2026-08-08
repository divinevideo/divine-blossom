import { SimplePool } from 'nostr-tools'
import type { Filter } from 'nostr-tools'
import type { NostrEvent } from '../types'
import {
  chunked,
  coordinateFilters,
  dedupeLatestLists,
  isEventReference,
  newestByCoordinate,
  profileNamesByPubkey,
} from './lists'
import type { ProfileMeta } from './lists'

export interface ListRelay {
  latestList(pubkey: string, dTag: string): Promise<NostrEvent | null>
  publish(event: NostrEvent): Promise<void>
}

export class DivineListRelay implements ListRelay {
  private readonly pool = new SimplePool()

  constructor(private readonly relays = ['wss://relay.divine.video']) {}

  async latestList(pubkey: string, dTag: string): Promise<NostrEvent | null> {
    const filter: Filter = {
      kinds: [30005],
      authors: [pubkey],
      '#d': [dTag],
      limit: 1,
    }
    const events = await this.pool.querySync(this.relays, filter, { maxWait: 10_000 })
    const latest = events.sort(
      (left, right) =>
        right.created_at - left.created_at || right.id.localeCompare(left.id),
    )[0]
    return (latest as NostrEvent | undefined) ?? null
  }

  async profile(pubkey: string): Promise<ProfileMeta | null> {
    const event = await this.pool.get(
      this.relays,
      { kinds: [0], authors: [pubkey], limit: 1 },
      { maxWait: 10_000 },
    )
    if (!event) return null
    try {
      const meta: unknown = JSON.parse(event.content)
      if (typeof meta !== 'object' || meta === null) return null
      return meta as ProfileMeta
    } catch {
      return null
    }
  }

  /** Display names for many authors in one query; missing profiles are absent. */
  async profileNames(pubkeys: string[]): Promise<Map<string, string>> {
    const authors = [...new Set(pubkeys.filter((pubkey) => /^[0-9a-f]{64}$/.test(pubkey)))]
    if (authors.length === 0) return new Map()
    const events = await Promise.all(
      chunked(authors).map((chunk) =>
        this.pool.querySync(this.relays, { kinds: [0], authors: chunk }, { maxWait: 10_000 }),
      ),
    )
    return profileNamesByPubkey(events.flat() as NostrEvent[])
  }

  async authoredLists(pubkey: string): Promise<NostrEvent[]> {
    const events = await this.pool.querySync(
      this.relays,
      { kinds: [30005], authors: [pubkey] },
      { maxWait: 10_000 },
    )
    return dedupeLatestLists(events as NostrEvent[])
  }

  async publish(event: NostrEvent): Promise<void> {
    const acknowledgements = this.pool.publish(this.relays, event, { maxWait: 10_000 })
    if (acknowledgements.length === 0) {
      throw new Error('No writable relay is configured.')
    }
    await Promise.any(acknowledgements)
  }

  /**
   * Resolves list references to video events. References are either `e` tag
   * event ids (Divine app lists) or `a` tag addressable coordinates (compiler
   * editor lists); the returned map is keyed by the reference as given.
   */
  async videoEvents(references: string[]): Promise<Map<string, NostrEvent>> {
    const eventIds = [...new Set(references.filter(isEventReference))]
    const coordinates = references.filter((reference) => !isEventReference(reference))

    const idFilters = chunked(eventIds).map((ids) => ({ ids }))
    const queries = [...idFilters, ...coordinateFilters(coordinates)].map((filter) =>
      this.pool.querySync(this.relays, filter as Filter, { maxWait: 10_000 }),
    )
    const events = (await Promise.all(queries)).flat() as NostrEvent[]

    const byId = new Map(events.map((event) => [event.id, event]))
    const byCoordinate = newestByCoordinate(events)
    const resolved = new Map<string, NostrEvent>()
    for (const reference of references) {
      const event = isEventReference(reference)
        ? byId.get(reference)
        : byCoordinate.get(reference)
      if (event) resolved.set(reference, event)
    }
    return resolved
  }

  close(): void {
    this.pool.destroy()
  }
}
