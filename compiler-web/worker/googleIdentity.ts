interface GoogleIdentityEnvironment {
  GOOGLE_SERVICE_ACCOUNT_EMAIL: string
  GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: string
}

const tokenCache = new Map<string, { token: string; expiresAt: number }>()

export async function getGoogleIdentityToken(
  environment: GoogleIdentityEnvironment,
  audience: string,
): Promise<string> {
  const cacheKey = `${environment.GOOGLE_SERVICE_ACCOUNT_EMAIL}\n${audience}`
  const cached = tokenCache.get(cacheKey)
  const now = Math.floor(Date.now() / 1000)
  if (cached && cached.expiresAt > now + 60) {
    return cached.token
  }

  const assertion = await serviceAccountAssertion(environment, audience, now)
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  })
  if (!response.ok) {
    throw new Error(`Google identity exchange failed (${response.status})`)
  }
  const payload = (await response.json()) as { id_token?: string }
  if (!payload.id_token) {
    throw new Error('Google identity exchange returned no id_token')
  }
  const expiresAt = jwtExpiry(payload.id_token)
  tokenCache.set(cacheKey, { token: payload.id_token, expiresAt })
  return payload.id_token
}

async function serviceAccountAssertion(
  environment: GoogleIdentityEnvironment,
  targetAudience: string,
  now: number,
): Promise<string> {
  const header = encodeJson({ alg: 'RS256', typ: 'JWT' })
  const claims = encodeJson({
    iss: environment.GOOGLE_SERVICE_ACCOUNT_EMAIL,
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
    target_audience: targetAudience,
  })
  const unsigned = `${header}.${claims}`
  const key = await crypto.subtle.importKey(
    'pkcs8',
    decodePem(environment.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(unsigned),
  )
  return `${unsigned}.${base64Url(new Uint8Array(signature))}`
}

function decodePem(value: string): ArrayBuffer {
  const normalized = value.replace(/\\n/g, '\n')
  const base64 = normalized
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '')
  const bytes = Uint8Array.from(atob(base64), (character) => character.charCodeAt(0))
  return bytes.buffer
}

function encodeJson(value: unknown): string {
  return base64Url(new TextEncoder().encode(JSON.stringify(value)))
}

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function jwtExpiry(token: string): number {
  const encoded = token.split('.')[1]
  if (!encoded) throw new Error('Google identity token is malformed')
  const base64 = encoded.replace(/-/g, '+').replace(/_/g, '/')
  const payload = JSON.parse(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')))
  if (typeof payload.exp !== 'number') {
    throw new Error('Google identity token has no expiry')
  }
  return payload.exp
}
