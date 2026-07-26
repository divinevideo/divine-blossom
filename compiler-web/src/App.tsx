import { ArrowRight, ListDashes, SpinnerGap } from '@phosphor-icons/react'
import { nip19 } from 'nostr-tools'
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  beginDivineLogin,
  completeDivineLoginCallback,
  logoutDivine,
  restoreDivineSigner,
} from './auth/divineLogin'
import { Header } from './components/Header'
import { Preview } from './components/Preview'
import { RecentJobs } from './components/RecentJobs'
import { RenderControls } from './components/RenderControls'
import { Timeline } from './components/Timeline'
import { createCompilation, getCompilation, getRecentJobs } from './compiler/api'
import {
  defaultRenders,
  fitForClip,
  hasUnsavedOrder,
  selectedRender,
  setClipFit,
  setDefaultFit,
} from './editorState'
import { listIdentifier, saveReorderedList, videoCoordinates } from './nostr/lists'
import { DivineListRelay } from './nostr/relay'
import type {
  Aspect,
  CompilationJob,
  FitMode,
  NostrEvent,
  NostrSigner,
  VideoClip,
} from './types'

export function App() {
  const relay = useMemo(() => new DivineListRelay(), [])
  const [signer, setSigner] = useState<NostrSigner | null>(null)
  const [pubkey, setPubkey] = useState<string>()
  const [authReady, setAuthReady] = useState(false)
  const [listReference, setListReference] = useState('')
  const [savedEvent, setSavedEvent] = useState<NostrEvent>()
  const [savedOrder, setSavedOrder] = useState<string[]>([])
  const [clips, setClips] = useState<VideoClip[]>([])
  const [selectedClip, setSelectedClip] = useState(0)
  const [selectedAspect, setSelectedAspect] = useState<Aspect>('9:16')
  const [renders, setRenders] = useState(defaultRenders)
  const [recentJobs, setRecentJobs] = useState<CompilationJob[]>([])
  const [loadingList, setLoadingList] = useState(false)
  const [saving, setSaving] = useState(false)
  const [rendering, setRendering] = useState(false)
  const [notice, setNotice] = useState<string>()
  const [error, setError] = useState<string>()

  const loadRecent = useCallback(async () => {
    try {
      setRecentJobs(await getRecentJobs())
    } catch {
      setRecentJobs([])
    }
  }, [])

  useEffect(() => {
    let active = true
    const restore = async () => {
      try {
        const nextSigner = window.location.pathname === '/auth/callback'
          ? await completeDivineLoginCallback()
          : await restoreDivineSigner()
        if (active && nextSigner) {
          setSigner(nextSigner)
          setPubkey(await nextSigner.getPublicKey())
          await loadRecent()
        }
      } catch (caught) {
        if (active) {
          setError(message(caught))
        }
      } finally {
        if (active) setAuthReady(true)
      }
    }
    void restore()
    return () => {
      active = false
    }
  }, [loadRecent, relay])

  const currentOrder = clips.map((clip) => clip.coordinate)
  const dirty = savedEvent
    ? hasUnsavedOrder(savedOrder, currentOrder)
    : false
  const currentClip = clips[selectedClip]
  const currentFit = currentClip
    ? fitForClip(renders, selectedAspect, currentClip.coordinate)
    : renders[selectedAspect].defaultFit
  const listName = savedEvent
    ? savedEvent.tags.find((tag) => tag[0] === 'title')?.[1] ??
      listIdentifier(savedEvent)
    : undefined

  const loadList = async () => {
    if (!signer || !pubkey) {
      setError('Connect Divine before opening an editorial list.')
      return
    }
    setLoadingList(true)
    setError(undefined)
    setNotice(undefined)
    try {
      const reference = parseListReference(listReference, pubkey)
      const event = await relay.latestList(reference.pubkey, reference.identifier)
      if (!event) throw new Error('No kind 30005 list matched that reference.')
      if (event.pubkey !== pubkey) {
        throw new Error('Connect the Divine identity that owns this list.')
      }
      const coordinates = videoCoordinates(event)
      const events = await relay.videoEvents(coordinates)
      const loaded = coordinates.map((coordinate) =>
        clipFromEvent(coordinate, events.get(coordinate)),
      )
      setSavedEvent(event)
      setSavedOrder(coordinates)
      setClips(loaded)
      setSelectedClip(0)
      setRenders(defaultRenders)
      setNotice(`Loaded ${loaded.length} clips in signed list order.`)
    } catch (caught) {
      setError(message(caught))
    } finally {
      setLoadingList(false)
    }
  }

  const reorder = (from: number, to: number) => {
    setClips((current) => {
      const next = [...current]
      const [moved] = next.splice(from, 1)
      next.splice(to, 0, moved)
      return next
    })
    setSelectedClip(to)
  }

  const saveList = async () => {
    if (!savedEvent || !signer) return
    setSaving(true)
    setError(undefined)
    try {
      const signed = await saveReorderedList(
        relay,
        signer,
        savedEvent,
        currentOrder,
      )
      setSavedEvent(signed)
      setSavedOrder(currentOrder)
      setNotice('Signed list order saved to the relay.')
    } catch (caught) {
      setError(message(caught))
    } finally {
      setSaving(false)
    }
  }

  const render = async () => {
    if (!savedEvent || !signer || dirty) return
    setRendering(true)
    setError(undefined)
    setNotice(`Queued ${selectedAspect} compilation…`)
    try {
      let job = await createCompilation(signer, savedEvent, [
        selectedRender(renders, selectedAspect),
      ])
      setRecentJobs((current) => upsertJob(current, job))
      for (let attempt = 0; attempt < 300 && !isTerminal(job); attempt += 1) {
        await new Promise((resolve) => window.setTimeout(resolve, 2_000))
        job = await getCompilation(job.id)
        setRecentJobs((current) => upsertJob(current, job))
      }
      if (job.status === 'done') {
        setNotice(`${selectedAspect} compilation is ready.`)
      } else if (job.status === 'failed') {
        throw new Error(job.error?.message ?? 'Compilation failed.')
      }
    } catch (caught) {
      setError(message(caught))
    } finally {
      setRendering(false)
      await loadRecent()
    }
  }

  const logout = () => {
    logoutDivine()
    setSigner(null)
    setPubkey(undefined)
    setSavedEvent(undefined)
    setClips([])
    setRecentJobs([])
  }

  if (!authReady) {
    return (
      <main className="auth-loading">
        <SpinnerGap size={30} className="spinner" />
        <span>Opening compiler…</span>
      </main>
    )
  }

  return (
    <div className="app-shell">
      <Header
        pubkey={pubkey}
        listName={listName}
        onLogin={() => void beginDivineLogin()}
        onLogout={logout}
      />
      <main>
        <section className="intro-row">
          <div>
            <span className="eyebrow">Editorial workspace</span>
            <h1>Shape a list into a cut.</h1>
            <p>
              Reorder the signed list, frame each clip, then render one external
              compilation. Nothing here publishes to Divine.
            </p>
          </div>
          <div className="list-loader">
            <label htmlFor="list-reference">Nostr list</label>
            <div>
              <ListDashes size={20} />
              <input
                id="list-reference"
                value={listReference}
                onChange={(event) => setListReference(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') void loadList()
                }}
                placeholder="naddr or 30005:pubkey:d-tag"
                disabled={!signer}
              />
              <button
                type="button"
                onClick={() => void loadList()}
                disabled={!signer || !listReference.trim() || loadingList}
                aria-label="Open list"
              >
                {loadingList ? <SpinnerGap className="spinner" /> : <ArrowRight />}
              </button>
            </div>
          </div>
        </section>

        {(error || notice) && (
          <div className={error ? 'notice error' : 'notice'} role="status">
            {error ?? notice}
          </div>
        )}

        <section className="workspace-grid">
          <Preview aspect={selectedAspect} clip={currentClip} fit={currentFit} />
          <Timeline
            clips={clips}
            selected={selectedClip}
            onSelect={setSelectedClip}
            onReorder={reorder}
          />
          <RenderControls
            aspect={selectedAspect}
            defaultFit={renders[selectedAspect].defaultFit}
            clipFit={currentFit}
            dirty={dirty}
            saving={saving}
            rendering={rendering}
            hasList={Boolean(savedEvent && clips.length)}
            onAspect={setSelectedAspect}
            onDefaultFit={(fit: FitMode) =>
              setRenders((current) => setDefaultFit(current, selectedAspect, fit))
            }
            onClipFit={(fit: FitMode) => {
              if (currentClip) {
                setRenders((current) =>
                  setClipFit(current, selectedAspect, currentClip.coordinate, fit),
                )
              }
            }}
            onSave={() => void saveList()}
            onRender={() => void render()}
          />
        </section>
        <RecentJobs jobs={recentJobs} />
      </main>
    </div>
  )
}

function parseListReference(
  value: string,
  fallbackPubkey: string,
): { pubkey: string; identifier: string } {
  const trimmed = value.trim()
  if (trimmed.startsWith('naddr1')) {
    const decoded = nip19.decode(trimmed)
    if (decoded.type !== 'naddr' || decoded.data.kind !== 30005) {
      throw new Error('The naddr must identify a kind 30005 list.')
    }
    return {
      pubkey: decoded.data.pubkey,
      identifier: decoded.data.identifier,
    }
  }
  if (!trimmed.includes(':')) {
    return { pubkey: fallbackPubkey, identifier: trimmed }
  }
  const [kind, pubkey, ...identifier] = trimmed.split(':')
  if (kind !== '30005' || !/^[0-9a-f]{64}$/.test(pubkey)) {
    throw new Error('Use a kind 30005 coordinate or naddr.')
  }
  return { pubkey, identifier: identifier.join(':') }
}

function clipFromEvent(coordinate: string, event?: NostrEvent): VideoClip {
  const title =
    event?.tags.find((tag) => tag[0] === 'title')?.[1] ??
    coordinate.split(':').slice(2).join(':')
  return {
    coordinate,
    event:
      event ??
      ({
        id: '',
        pubkey: coordinate.split(':')[1],
        created_at: 0,
        kind: Number(coordinate.split(':')[0]),
        tags: [],
        content: '',
        sig: '',
      } satisfies NostrEvent),
    videoUrl: event ? mediaUrl(event) : undefined,
    title,
    creator: event ? `${event.pubkey.slice(0, 10)}…` : 'Missing event',
  }
}

function mediaUrl(event: NostrEvent): string | undefined {
  for (const tag of event.tags) {
    if (tag[0] === 'imeta') {
      const url = tag.slice(1).find((value) => value.startsWith('url '))?.slice(4)
      const mime = tag.slice(1).find((value) => value.startsWith('m '))?.slice(2)
      if (url && mime === 'video/mp4') return url
    }
    if (tag[0] === 'url' && tag[1]) return tag[1]
  }
  return undefined
}

function upsertJob(jobs: CompilationJob[], next: CompilationJob): CompilationJob[] {
  return [next, ...jobs.filter((job) => job.id !== next.id)].slice(0, 20)
}

function isTerminal(job: CompilationJob): boolean {
  return job.status === 'done' || job.status === 'failed'
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : 'Something went wrong.'
}
