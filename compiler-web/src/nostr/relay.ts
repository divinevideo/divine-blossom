import { SimplePool } from 'nostr-tools'
import type { Filter } from 'nostr-tools'
import type { NostrEvent } from '../types'

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

  async publish(event: NostrEvent): Promise<void> {
    const acknowledgements = this.pool.publish(this.relays, event, { maxWait: 10_000 })
    if (acknowledgements.length === 0) {
      throw new Error('No writable relay is configured.')
    }
    await Promise.any(acknowledgements)
  }

  close(): void {
    this.pool.destroy()
  }
}
