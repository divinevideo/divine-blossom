import type {
  CompilationJob,
  NostrEvent,
  NostrSigner,
  RenderRequest,
} from '../types'

export async function createCompilation(
  signer: NostrSigner,
  savedEvent: NostrEvent,
  renders: RenderRequest[],
): Promise<CompilationJob> {
  const body = JSON.stringify({
    source: { list_event: savedEvent },
    renders,
  })
  const publicUrl = new URL('/api/compile', window.location.origin).toString()
  const authorization = await nip98Authorization(signer, publicUrl, 'POST', body)
  const response = await fetch('/api/compile', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: authorization,
    },
    body,
  })
  const payload = await response.json()
  if (!response.ok) {
    throw new Error(payload.error ?? `Compilation request failed (${response.status})`)
  }
  return payload.job as CompilationJob
}

export async function getCompilation(id: string): Promise<CompilationJob> {
  const response = await fetch(`/api/compile/${encodeURIComponent(id)}`)
  if (!response.ok) {
    throw new Error(`Could not load compilation (${response.status})`)
  }
  return (await response.json()) as CompilationJob
}

export async function getRecentJobs(): Promise<CompilationJob[]> {
  const response = await fetch('/api/jobs')
  if (!response.ok) {
    throw new Error(`Could not load recent compilations (${response.status})`)
  }
  return (await response.json()) as CompilationJob[]
}

async function nip98Authorization(
  signer: NostrSigner,
  url: string,
  method: string,
  body: string,
): Promise<string> {
  const payload = await sha256Hex(body)
  const event = await signer.signEvent({
    kind: 27235,
    content: '',
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ['u', url],
      ['method', method],
      ['payload', payload],
    ],
  })
  return `Nostr ${btoa(JSON.stringify(event))}`
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}
