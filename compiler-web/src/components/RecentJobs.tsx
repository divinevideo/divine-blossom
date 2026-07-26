import { Copy, DownloadSimple } from '@phosphor-icons/react'
import type { CompilationJob } from '../types'

interface RecentJobsProps {
  jobs: CompilationJob[]
}

export function RecentJobs({ jobs }: RecentJobsProps) {
  return (
    <section className="recent-section">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Archive</span>
          <h2>Recent compilations</h2>
        </div>
        <span>{jobs.length} jobs</span>
      </div>
      {jobs.length === 0 ? (
        <div className="empty-jobs">Completed renders will appear here.</div>
      ) : (
        <div className="job-grid">
          {jobs.map((job) => (
            <article className="job-card" key={job.id}>
              <div className="job-meta">
                <span className={`status status-${job.status}`}>{job.status}</span>
                <time>{new Date(job.created_at * 1000).toLocaleString()}</time>
              </div>
              {job.result?.outputs.map((output) => (
                <div className="output-item" key={`${job.id}-${output.aspect}`}>
                  <video src={output.url} controls preload="metadata" />
                  <div className="output-actions">
                    <strong>{output.aspect}</strong>
                    <a href={output.url} download className="icon-action">
                      <DownloadSimple size={17} />
                      Download
                    </a>
                    <button
                      type="button"
                      className="icon-action"
                      onClick={() => navigator.clipboard.writeText(output.url)}
                    >
                      <Copy size={17} />
                      Copy URL
                    </button>
                  </div>
                </div>
              ))}
              {job.error && <p className="job-error">{job.error.message}</p>}
            </article>
          ))}
        </div>
      )}
    </section>
  )
}
