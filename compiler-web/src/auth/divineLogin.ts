import { createDivineClient } from '@divinevideo/login'
import { HostedDivineSigner } from './signer'

const login = createDivineClient({
  serverUrl: 'https://login.divine.video',
  clientId: 'compiler-divine-video',
  redirectUri: new URL('/auth/callback', window.location.origin).toString(),
  storage: localStorage,
})

export async function beginDivineLogin(): Promise<void> {
  const { url } = await login.oauth.getAuthorizationUrl({
    scopes: ['policy:full'],
  })
  window.location.assign(url)
}

export async function completeDivineLoginCallback(): Promise<HostedDivineSigner> {
  const callback = login.oauth.parseCallback(window.location.href)
  if ('error' in callback) {
    throw new Error(callback.description ?? callback.error)
  }
  const response = await login.oauth.exchangeCode(callback.code)
  if (!response.access_token) {
    throw new Error('Divine login did not return a hosted signing session.')
  }
  window.history.replaceState({}, '', '/')
  return signerFromToken(response.access_token)
}

export async function restoreDivineSigner(): Promise<HostedDivineSigner | null> {
  const session = await login.oauth.getSessionWithRefresh()
  return session?.accessToken ? signerFromToken(session.accessToken) : null
}

export function logoutDivine(): void {
  login.oauth.logout()
}

function signerFromToken(accessToken: string): HostedDivineSigner {
  return new HostedDivineSigner(accessToken, async () => {
    const refreshed = await login.oauth.getSessionWithRefresh()
    if (!refreshed?.accessToken) {
      throw new Error('Divine signing session expired.')
    }
    return refreshed.accessToken
  })
}
