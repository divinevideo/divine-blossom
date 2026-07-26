import { describe, expect, it } from 'vitest'
import {
  fitForClip,
  hasUnsavedOrder,
  setClipFit,
  type EditorRenders,
} from './editorState'

const a = `34236:${'a'.repeat(64)}:a`
const b = `34236:${'b'.repeat(64)}:b`

describe('editor state', () => {
  it('detects unsaved reorder so Render can remain disabled', () => {
    expect(hasUnsavedOrder([a, b], [b, a])).toBe(true)
    expect(hasUnsavedOrder([a, b], [a, b])).toBe(false)
  })

  it('keeps clip fit overrides scoped to one aspect', () => {
    const renders: EditorRenders = {
      '9:16': { defaultFit: 'blur-pad', overrides: {} },
      '1:1': { defaultFit: 'center-crop', overrides: {} },
      '16:9': { defaultFit: 'letterbox', overrides: {} },
    }
    const changed = setClipFit(renders, '9:16', a, 'center-crop')

    expect(fitForClip(changed, '9:16', a)).toBe('center-crop')
    expect(fitForClip(changed, '1:1', a)).toBe('center-crop')
    expect(changed['1:1'].overrides).toEqual({})
  })
})
