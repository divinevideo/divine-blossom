import { FilmStrip } from '@phosphor-icons/react'
import type { Aspect, FitMode, VideoClip } from '../types'

interface PreviewProps {
  aspect: Aspect
  clip?: VideoClip
  fit: FitMode
}

export function Preview({ aspect, clip, fit }: PreviewProps) {
  return (
    <section className="panel preview-panel" aria-label="Selected clip preview">
      <div className="panel-label">
        <span>Preview</span>
        <span>
          {aspect} · {fit}
        </span>
      </div>
      <div className={`preview-frame aspect-${aspect.replace(':', '-')}`}>
        {clip?.videoUrl ? (
          <video
            key={clip.videoUrl}
            src={clip.videoUrl}
            controls
            playsInline
            preload="metadata"
            className={`fit-${fit}`}
          />
        ) : (
          <div className="preview-empty">
            <FilmStrip size={34} />
            <span>{clip ? 'Source unavailable' : 'Choose a list to begin'}</span>
          </div>
        )}
      </div>
      {clip && (
        <div className="preview-caption">
          <strong>{clip.title}</strong>
          <span>{clip.creator}</span>
        </div>
      )}
    </section>
  )
}
