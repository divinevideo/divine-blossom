import { beforeEach, describe, expect, it, vi } from 'vitest'
import { getGoogleIdentityToken } from './googleIdentity'
import worker, { type Environment } from './index'

vi.mock('./googleIdentity', () => ({
  getGoogleIdentityToken: vi.fn().mockResolvedValue('google-identity-token'),
}))

function environment(): Environment {
  return {
    ASSETS: {
      fetch: vi.fn().mockResolvedValue(new Response('asset')),
    },
    COMPILER_SERVICE_URL: 'https://compiler-service.example.run.app',
    GOOGLE_SERVICE_ACCOUNT_EMAIL: 'compiler-edge@example.iam.gserviceaccount.com',
    GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: 'secret',
  }
}

describe('compiler edge', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.mocked(getGoogleIdentityToken).mockResolvedValue('google-identity-token')
  })

  it('rejects requests without Cloudflare Access identity', async () => {
    const response = await worker.fetch(
      new Request('https://compiler.divine.video/'),
      environment(),
    )

    expect(response.status).toBe(401)
  })

  it('passes protected static requests to the assets binding', async () => {
    const env = environment()
    const request = new Request('https://compiler.divine.video/')
    request.headers.set('CF-Access-Authenticated-User-Email', 'curator@divine.video')

    await expect(worker.fetch(request, env)).resolves.toHaveProperty('status', 200)
    expect(env.ASSETS.fetch).toHaveBeenCalledWith(request)
    expect(getGoogleIdentityToken).not.toHaveBeenCalled()
  })

  it('overwrites browser identity and forwards NIP-98 separately', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('ok'))
    const request = new Request('https://compiler.divine.video/api/compile', {
      method: 'POST',
      headers: {
        'CF-Access-Authenticated-User-Email': 'Curator@Divine.Video',
        'X-Compiler-Initiated-By': 'forged@divine.video',
        Authorization: 'Nostr signed-event',
      },
      body: '{}',
    })

    await worker.fetch(request, environment())

    const backendRequest = fetchMock.mock.calls[0][0] as Request
    expect(backendRequest.url).toBe(
      'https://compiler-service.example.run.app/api/compile',
    )
    expect(backendRequest.headers.get('X-Compiler-Initiated-By')).toBe(
      'curator@divine.video',
    )
    expect(backendRequest.headers.get('X-Compiler-Nostr-Authorization')).toBe(
      'Nostr signed-event',
    )
    expect(backendRequest.headers.get('Authorization')).toBe(
      'Bearer google-identity-token',
    )
  })
})
