import { afterEach, describe, expect, it, vi } from 'vitest'
import { getGoogleIdentityToken } from './googleIdentity'

describe('Google Cloud Run identity exchange', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('mints and caches a target-audience token without domain-wide delegation', async () => {
    const privateKey = await generatePrivateKeyPem()
    const idToken = unsignedJwt({ exp: Math.floor(Date.now() / 1000) + 3600 })
    const tokenFetch = vi.fn().mockResolvedValue(
      Response.json({ id_token: idToken }),
    )
    vi.stubGlobal('fetch', tokenFetch)

    const environment = {
      GOOGLE_SERVICE_ACCOUNT_EMAIL:
        'compiler-edge-production@example.iam.gserviceaccount.com',
      GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: privateKey,
    }
    const audience = 'https://compiler-service.example.run.app'

    expect(await getGoogleIdentityToken(environment, audience)).toBe(idToken)
    expect(await getGoogleIdentityToken(environment, audience)).toBe(idToken)
    expect(tokenFetch).toHaveBeenCalledTimes(1)

    const [, init] = tokenFetch.mock.calls[0] as [string, RequestInit]
    const assertion = (init.body as URLSearchParams).get('assertion')
    expect(assertion).toBeTruthy()
    const claims = decodeJwtPayload(assertion!)

    expect(claims).toMatchObject({
      iss: environment.GOOGLE_SERVICE_ACCOUNT_EMAIL,
      aud: 'https://oauth2.googleapis.com/token',
      target_audience: audience,
    })
    expect(claims).not.toHaveProperty('sub')
  })
})

async function generatePrivateKeyPem(): Promise<string> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
  const base64 = Buffer.from(pkcs8).toString('base64')
  const lines = base64.match(/.{1,64}/g)?.join('\n') ?? base64
  return `-----BEGIN PRIVATE KEY-----\n${lines}\n-----END PRIVATE KEY-----`
}

function unsignedJwt(payload: Record<string, unknown>): string {
  return `e30.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.signature`
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'))
}
