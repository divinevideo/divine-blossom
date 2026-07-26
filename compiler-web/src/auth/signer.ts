import { DivineRpc } from '@divinevideo/login'
import { verifyEvent } from 'nostr-tools'
import type { NostrEvent, NostrSigner, UnsignedNostrEvent } from '../types'

export class HostedDivineSigner implements NostrSigner {
  private readonly rpc: DivineRpc
  private pubkey?: string

  constructor(accessToken: string, refresh?: () => Promise<string>) {
    this.rpc = new DivineRpc({
      nostrApi: 'https://login.divine.video/api/nostr',
      accessToken,
      onUnauthorized: refresh,
    })
  }

  async getPublicKey(): Promise<string> {
    this.pubkey ??= await this.rpc.getPublicKey()
    return this.pubkey
  }

  async signEvent(
    event: Omit<UnsignedNostrEvent, 'pubkey'> | UnsignedNostrEvent,
  ): Promise<NostrEvent> {
    const pubkey = await this.getPublicKey()
    const signed = (await this.rpc.signEvent({
      ...event,
      pubkey,
    })) as NostrEvent
    if (!verifyEvent(signed)) {
      throw new Error('The hosted signer returned an invalid signature.')
    }
    return signed
  }
}
