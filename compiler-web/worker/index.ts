import { getGoogleIdentityToken } from './googleIdentity'

interface AssetBinding {
  fetch(request: Request): Promise<Response>
}

export interface Environment {
  ASSETS: AssetBinding
  COMPILER_SERVICE_URL: string
  GOOGLE_SERVICE_ACCOUNT_EMAIL: string
  GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: string
}

const worker = {
  async fetch(request: Request, environment: Environment): Promise<Response> {
    const accessIdentity = request.headers.get('CF-Access-Authenticated-User-Email')
    if (!accessIdentity) {
      return Response.json(
        { error: 'Cloudflare Access identity required' },
        { status: 401 },
      )
    }

    const url = new URL(request.url)
    if (!url.pathname.startsWith('/api/')) {
      return environment.ASSETS.fetch(request)
    }

    const serviceUrl = validateServiceUrl(environment.COMPILER_SERVICE_URL)
    const backendUrl = new URL(`${url.pathname}${url.search}`, serviceUrl)
    const headers = new Headers(request.headers)
    const nostrAuthorization = headers.get('Authorization')
    if (nostrAuthorization && !nostrAuthorization.startsWith('Nostr ')) {
      return Response.json({ error: 'Invalid Nostr authorization scheme' }, { status: 401 })
    }
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && !nostrAuthorization) {
      return Response.json({ error: 'Nostr authorization required' }, { status: 401 })
    }
    headers.delete('Authorization')
    headers.delete('X-Compiler-Initiated-By')
    headers.delete('X-Compiler-Nostr-Authorization')
    headers.set('X-Compiler-Initiated-By', accessIdentity.toLowerCase())
    if (nostrAuthorization) {
      headers.set('X-Compiler-Nostr-Authorization', nostrAuthorization)
    }
    const identityToken = await getGoogleIdentityToken(environment, serviceUrl)
    headers.set('Authorization', `Bearer ${identityToken}`)
    const body = ['GET', 'HEAD'].includes(request.method)
      ? undefined
      : await request.arrayBuffer()

    return fetch(
      new Request(backendUrl, {
        method: request.method,
        headers,
        body,
        redirect: 'manual',
      }),
    )
  },
}

export default worker

function validateServiceUrl(value: string): string {
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('COMPILER_SERVICE_URL must be an HTTPS origin')
  }
  return url.origin
}
