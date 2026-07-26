export type NostrTag = string[]

export interface NostrEvent {
  id: string
  pubkey: string
  created_at: number
  kind: number
  tags: NostrTag[]
  content: string
  sig: string
}

export interface UnsignedNostrEvent {
  pubkey: string
  created_at: number
  kind: number
  tags: NostrTag[]
  content: string
}

export interface NostrSigner {
  getPublicKey(): Promise<string>
  signEvent(event: Omit<UnsignedNostrEvent, 'pubkey'> | UnsignedNostrEvent): Promise<NostrEvent>
}

export type Aspect = '9:16' | '1:1' | '16:9'
export type FitMode = 'blur-pad' | 'center-crop' | 'letterbox'

export interface RenderRequest {
  aspect: Aspect
  default_fit: FitMode
  clip_overrides: Array<{ coordinate: string; fit: FitMode }>
}
