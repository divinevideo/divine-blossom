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

export type JobStatus = 'queued' | 'running' | 'done' | 'failed'

export interface CompilationOutput {
  aspect: Aspect
  url: string
  sha256: string
  size: number
  dim: string
}

export interface CompilationJob {
  id: string
  status: JobStatus
  progress: number
  initiated_by: string
  created_at: number
  updated_at: number
  result?: {
    outputs: CompilationOutput[]
    aspect_failures: Array<{ aspect: Aspect; code: string; message: string }>
    duration_sec: number
    clips_used: number
    clips_dropped: Array<{
      source_index: number
      coordinate: string
      reason: string
    }>
  }
  error?: { code: string; message: string }
}

export interface VideoClip {
  coordinate: string
  event: NostrEvent
  videoUrl?: string
  title: string
  creator: string
}
