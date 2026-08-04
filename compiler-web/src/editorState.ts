import type { Aspect, FitMode, RenderRequest } from './types'

export interface AspectSettings {
  defaultFit: FitMode
  overrides: Record<string, FitMode>
}

export type EditorRenders = Record<Aspect, AspectSettings>

export const defaultRenders: EditorRenders = {
  '9:16': { defaultFit: 'blur-pad', overrides: {} },
  '1:1': { defaultFit: 'blur-pad', overrides: {} },
  '16:9': { defaultFit: 'blur-pad', overrides: {} },
}

export function hasUnsavedOrder(saved: string[], current: string[]): boolean {
  return (
    saved.length !== current.length ||
    saved.some((reference, index) => reference !== current[index])
  )
}

export function fitForClip(
  renders: EditorRenders,
  aspect: Aspect,
  reference: string,
): FitMode {
  return renders[aspect].overrides[reference] ?? renders[aspect].defaultFit
}

export function setDefaultFit(
  renders: EditorRenders,
  aspect: Aspect,
  fit: FitMode,
): EditorRenders {
  return {
    ...renders,
    [aspect]: { ...renders[aspect], defaultFit: fit },
  }
}

export function setClipFit(
  renders: EditorRenders,
  aspect: Aspect,
  reference: string,
  fit: FitMode,
): EditorRenders {
  const settings = renders[aspect]
  const overrides = { ...settings.overrides }
  if (fit === settings.defaultFit) {
    delete overrides[reference]
  } else {
    overrides[reference] = fit
  }
  return {
    ...renders,
    [aspect]: { ...settings, overrides },
  }
}

export function selectedRender(
  renders: EditorRenders,
  aspect: Aspect,
): RenderRequest {
  const settings = renders[aspect]
  return {
    aspect,
    default_fit: settings.defaultFit,
    clip_overrides: Object.entries(settings.overrides).map(([reference, fit]) => ({
      coordinate: reference,
      fit,
    })),
  }
}
