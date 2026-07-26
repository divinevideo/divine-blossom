import { DotsSixVertical, WarningCircle } from '@phosphor-icons/react'
import { useState } from 'react'
import type { VideoClip } from '../types'

interface TimelineProps {
  clips: VideoClip[]
  selected: number
  onSelect: (index: number) => void
  onReorder: (from: number, to: number) => void
}

export function Timeline({ clips, selected, onSelect, onReorder }: TimelineProps) {
  const [dragging, setDragging] = useState<number>()

  return (
    <section className="panel timeline-panel">
      <div className="panel-label">
        <span>Timeline</span>
        <span>{clips.length} clips · drag to reorder</span>
      </div>
      <ol className="timeline-list">
        {clips.map((clip, index) => (
          <li
            key={clip.coordinate}
            className={selected === index ? 'timeline-item selected' : 'timeline-item'}
            draggable
            onDragStart={() => setDragging(index)}
            onDragOver={(event) => event.preventDefault()}
            onDrop={() => {
              if (dragging !== undefined && dragging !== index) {
                onReorder(dragging, index)
              }
              setDragging(undefined)
            }}
          >
            <button type="button" onClick={() => onSelect(index)}>
              <DotsSixVertical className="drag-handle" size={20} weight="bold" />
              <span className="clip-number">{String(index + 1).padStart(2, '0')}</span>
              <span className="clip-copy">
                <strong>{clip.title}</strong>
                <small>{clip.creator}</small>
              </span>
              {!clip.videoUrl && (
                <WarningCircle
                  size={18}
                  className="warning-icon"
                  aria-label="Source unavailable"
                />
              )}
            </button>
          </li>
        ))}
      </ol>
    </section>
  )
}
