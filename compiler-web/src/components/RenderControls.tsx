import { FloppyDisk, Play } from '@phosphor-icons/react'
import type { Aspect, FitMode } from '../types'

const aspects: Aspect[] = ['9:16', '1:1', '16:9']
const fits: Array<{ value: FitMode; label: string }> = [
  { value: 'blur-pad', label: 'Blur pad' },
  { value: 'center-crop', label: 'Center crop' },
  { value: 'letterbox', label: 'Letterbox' },
]

interface RenderControlsProps {
  aspect: Aspect
  defaultFit: FitMode
  clipFit: FitMode
  dirty: boolean
  saving: boolean
  rendering: boolean
  hasList: boolean
  onAspect: (aspect: Aspect) => void
  onDefaultFit: (fit: FitMode) => void
  onClipFit: (fit: FitMode) => void
  onSave: () => void
  onRender: () => void
}

export function RenderControls(props: RenderControlsProps) {
  return (
    <section className="panel controls-panel">
      <div className="panel-label">
        <span>Output</span>
        {props.dirty && <span className="unsaved-dot">Unsaved order</span>}
      </div>
      <div className="aspect-tabs" aria-label="Output aspect">
        {aspects.map((aspect) => (
          <button
            type="button"
            key={aspect}
            className={props.aspect === aspect ? 'active' : ''}
            onClick={() => props.onAspect(aspect)}
          >
            {aspect}
          </button>
        ))}
      </div>
      <label className="field-label" htmlFor="default-fit">
        Default framing
      </label>
      <select
        id="default-fit"
        value={props.defaultFit}
        onChange={(event) => props.onDefaultFit(event.target.value as FitMode)}
      >
        {fits.map((fit) => (
          <option key={fit.value} value={fit.value}>
            {fit.label}
          </option>
        ))}
      </select>
      <label className="field-label" htmlFor="clip-fit">
        Selected clip framing
      </label>
      <select
        id="clip-fit"
        value={props.clipFit}
        onChange={(event) => props.onClipFit(event.target.value as FitMode)}
        disabled={!props.hasList}
      >
        {fits.map((fit) => (
          <option key={fit.value} value={fit.value}>
            {fit.label}
          </option>
        ))}
      </select>
      <div className="control-actions">
        <button
          className="button secondary"
          type="button"
          onClick={props.onSave}
          disabled={!props.hasList || !props.dirty || props.saving}
        >
          <FloppyDisk size={18} />
          {props.saving ? 'Saving…' : 'Save list'}
        </button>
        <button
          className="button primary"
          type="button"
          onClick={props.onRender}
          disabled={!props.hasList || props.dirty || props.rendering}
        >
          <Play size={18} weight="fill" />
          {props.rendering ? 'Rendering…' : `Render ${props.aspect}`}
        </button>
      </div>
      {props.dirty && (
        <p className="control-note">Save the signed list order before rendering.</p>
      )}
    </section>
  )
}
