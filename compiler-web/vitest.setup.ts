import { afterEach } from 'vitest'

afterEach(() => {
  globalThis.localStorage?.clear()
  globalThis.sessionStorage?.clear()
})
