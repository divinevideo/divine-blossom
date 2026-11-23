-- Production-capable SQL schema for Bunny Blossom edge runtime (libSQL / SQLite).
-- Atomic revision CAS on blobs + indexed owner table for cursor-paginated GET /list/<pubkey>.

CREATE TABLE IF NOT EXISTS blobs (
  hash TEXT PRIMARY KEY CHECK(length(hash) = 64),
  revision INTEGER NOT NULL CHECK(revision > 0),
  status TEXT NOT NULL,
  age_restricted INTEGER NOT NULL DEFAULT 0,
  held INTEGER NOT NULL DEFAULT 0,
  size INTEGER NOT NULL DEFAULT 0,
  mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
  uploaded INTEGER NOT NULL DEFAULT 0,
  owner TEXT NOT NULL DEFAULT '',
  transcode_status TEXT,
  transcode_generation INTEGER,
  transcript_status TEXT,
  transcript_generation INTEGER,
  gate TEXT,
  cleanup_pending INTEGER NOT NULL DEFAULT 0,
  body TEXT NOT NULL CHECK(json_valid(body))
);

CREATE INDEX IF NOT EXISTS idx_blobs_uploaded ON blobs(uploaded DESC, hash ASC);
CREATE INDEX IF NOT EXISTS idx_blobs_status ON blobs(status);
CREATE INDEX IF NOT EXISTS idx_blobs_cleanup ON blobs(cleanup_pending) WHERE cleanup_pending = 1;

CREATE TABLE IF NOT EXISTS blob_owners (
  owner TEXT NOT NULL CHECK(length(owner) = 64),
  hash TEXT NOT NULL CHECK(length(hash) = 64),
  uploaded INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (owner, hash)
);

CREATE INDEX IF NOT EXISTS idx_blob_owners_list ON blob_owners(owner, uploaded DESC, hash ASC);

CREATE TABLE IF NOT EXISTS quarantine_holds (
  hash TEXT NOT NULL CHECK(length(hash) = 64),
  hold_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (hash, hold_id)
);

CREATE TABLE IF NOT EXISTS subtitles (
  job_id TEXT PRIMARY KEY,
  video_sha256 TEXT NOT NULL CHECK(length(video_sha256) = 64),
  lang TEXT NOT NULL DEFAULT 'en',
  status TEXT NOT NULL,
  vtt_key TEXT,
  error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_subtitles_hash ON subtitles(video_sha256, lang);

CREATE TABLE IF NOT EXISTS purge_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hash TEXT NOT NULL CHECK(length(hash) = 64),
  reason TEXT NOT NULL,
  delete_b2 INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_retry_at INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_purge_outbox_due ON purge_outbox(next_retry_at, id);
