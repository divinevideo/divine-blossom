import { ArrowRight, ListDashes, SpinnerGap } from '@phosphor-icons/react'
import { nip19 } from 'nostr-tools'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
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
import {
  displayNameFromProfile,
  isEventReference,
  listIdentifier,
  saveReorderedList,
  videoReferences,
} from './nostr/lists'
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
  const loadedListIdRef = useRef<string>()
  const [signer, setSigner] = useState<NostrSigner | null>(null)
  const [pubkey, setPubkey] = useState<string>()
  const [displayName, setDisplayName] = useState<string>()
  const [myLists, setMyLists] = useState<NostrEvent[]>()
  const [myListsLoading, setMyListsLoading] = useState(false)
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
          const nextPubkey = await nextSigner.getPublicKey()
          setPubkey(nextPubkey)
          setMyListsLoading(true)
          relay
            .profile(nextPubkey)
            .then((meta) => {
              if (active) setDisplayName(displayNameFromProfile(meta))
            })
            .catch(() => {})
          relay
            .authoredLists(nextPubkey)
            .then((lists) => {
              if (active) setMyLists(lists)
            })
            .catch(() => {})
            .finally(() => {
              if (active) setMyListsLoading(false)
            })
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

  const currentOrder = clips.map((clip) => clip.reference)
  const dirty = savedEvent
    ? hasUnsavedOrder(savedOrder, currentOrder)
    : false
  const currentClip = clips[selectedClip]
  const currentFit = currentClip
    ? fitForClip(renders, selectedAspect, currentClip.reference)
    : renders[selectedAspect].defaultFit
  const listName = savedEvent
    ? savedEvent.tags.find((tag) => tag[0] === 'title')?.[1] ??
      listIdentifier(savedEvent)
    : undefined

  const loadList = async (referenceValue = listReference) => {
    if (!signer || !pubkey) {
      setError('Connect Divine before opening an editorial list.')
      return
    }
    setLoadingList(true)
    setError(undefined)
    setNotice(undefined)
    try {
      const reference = parseListReference(referenceValue, pubkey)
      const event = await relay.latestList(reference.pubkey, reference.identifier)
      if (!event) throw new Error('No kind 30005 list matched that reference.')
      if (event.pubkey !== pubkey) {
        throw new Error('Connect the Divine identity that owns this list.')
      }
      const references = videoReferences(event)
      const events = await relay.videoEvents(references)
      const loaded = references.map((reference) =>
        clipFromEvent(reference, events.get(reference)),
      )
      loadedListIdRef.current = event.id
      setSavedEvent(event)
      setSavedOrder(references)
      setClips(loaded)
      setSelectedClip(0)
      setRenders(defaultRenders)
      setNotice(`Loaded ${loaded.length} clips in signed list order.`)
      void applyCreatorNames(event.id, loaded)
    } catch (caught) {
      setError(message(caught))
    } finally {
      setLoadingList(false)
    }
  }

  /**
   * Creator names are an enhancement over the npub fallback: they land after
   * the clips render, never block the load, and are dropped if another list
   * was opened meanwhile.
   */
  const applyCreatorNames = async (listEventId: string, loaded: VideoClip[]) => {
    try {
      const names = await relay.profileNames(
        loaded.map((clip) => clip.event.pubkey),
      )
      if (names.size === 0) return
      setClips((current) => {
        if (loadedListIdRef.current !== listEventId) return current
        return current.map((clip) => {
          const name = names.get(clip.event.pubkey)
          return name ? { ...clip, creator: name } : clip
        })
      })
    } catch {
      // Keep the npub fallback when the relay cannot serve profiles.
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
    loadedListIdRef.current = undefined
    setSigner(null)
    setPubkey(undefined)
    setDisplayName(undefined)
    setMyLists(undefined)
    setMyListsLoading(false)
    setSavedEvent(undefined)
    setClips([])
    setRecentJobs([])
  }

  const openAuthoredList = (event: NostrEvent) => {
    const coordinate = `30005:${event.pubkey}:${listIdentifier(event)}`
    setListReference(coordinate)
    void loadList(coordinate)
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
        displayName={displayName}
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
            {signer && (
              <div className="my-lists">
                {myListsLoading && (
                  <div className="my-lists-row loading">
                    <SpinnerGap className="spinner" size={16} />
                    <span>Finding your lists…</span>
                  </div>
                )}
                {!myListsLoading && myLists && myLists.length === 0 && (
                  <div className="my-lists-row empty">No lists found on relay.</div>
                )}
                {!myListsLoading &&
                  myLists?.map((event) => {
                    const identifier = event.tags.find(
                      (tag) => tag[0] === 'd' && typeof tag[1] === 'string' && tag[1],
                    )?.[1]
                    if (!identifier) return null
                    return (
                      <button
                        key={event.id}
                        type="button"
                        className="my-lists-row"
                        onClick={() => openAuthoredList(event)}
                      >
                        <span className="my-lists-title">
                          {event.tags.find((tag) => tag[0] === 'title')?.[1] ??
                            identifier}
                        </span>
                        <span className="my-lists-count">
                          {videoReferences(event).length} clips
                        </span>
                      </button>
                    )
                  })}
              </div>
            )}
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
                  setClipFit(current, selectedAspect, currentClip.reference, fit),
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

function clipFromEvent(reference: string, event?: NostrEvent): VideoClip {
  const listedById = isEventReference(reference)
  const fallbackTitle = listedById
    ? `${reference.slice(0, 12)}…`
    : reference.split(':').slice(2).join(':')
  const title = event?.tags.find((tag) => tag[0] === 'title')?.[1] ?? fallbackTitle
  return {
    reference,
    event:
      event ??
      ({
        id: listedById ? reference : '',
        pubkey: listedById ? '' : reference.split(':')[1],
        created_at: 0,
        kind: listedById ? 0 : Number(reference.split(':')[0]),
        tags: [],
        content: '',
        sig: '',
      } satisfies NostrEvent),
    videoUrl: event ? mediaUrl(event) : undefined,
    title,
    creator: event ? shortNpub(event.pubkey) : 'Missing event',
  }
}

/** Readable stand-in until the kind 0 profile name arrives. */
function shortNpub(pubkey: string): string {
  if (!/^[0-9a-f]{64}$/.test(pubkey)) return 'Unknown creator'
  const npub = nip19.npubEncode(pubkey)
  return `${npub.slice(0, 12)}…${npub.slice(-4)}`
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
