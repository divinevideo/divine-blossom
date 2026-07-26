import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { NostrEvent, NostrSigner, RenderRequest } from '../types'
import { createCompilation } from './api'

const listEvent: NostrEvent = {
  id: 'a'.repeat(64),
  pubkey: 'b'.repeat(64),
  created_at: 100,
  kind: 30005,
  tags: [['d', 'staff-picks']],
  content: '',
  sig: 'c'.repeat(128),
}
const renders: RenderRequest[] = [
  { aspect: '9:16', default_fit: 'blur-pad', clip_overrides: [] },
]

describe('compiler API', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('posts the exact saved event snapshot and signed exact body', async () => {
    const signer: NostrSigner = {
      getPublicKey: vi.fn().mockResolvedValue(listEvent.pubkey),
      signEvent: vi.fn().mockImplementation(async (event) => ({
        ...event,
        pubkey: listEvent.pubkey,
        id: 'd'.repeat(64),
        sig: 'e'.repeat(128),
      })),
    }
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          status: 'queued',
          job: { id: 'job-1', status: 'queued' },
        }),
        { status: 202, headers: { 'content-type': 'application/json' } },
      ),
    )

    await createCompilation(signer, listEvent, renders)

    const expectedBody = JSON.stringify({
      source: { list_event: listEvent },
      renders,
    })
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/compile',
      expect.objectContaining({
        method: 'POST',
        body: expectedBody,
      }),
    )
    expect(signer.signEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: 27235,
        tags: expect.arrayContaining([
          ['u', 'https://compiler.divine.video/api/compile'],
          ['method', 'POST'],
        ]),
      }),
    )
  })
})
