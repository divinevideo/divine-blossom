-- Owned synthetic fixtures only. No production metadata importer is supplied.
CREATE TABLE IF NOT EXISTS spike_blobs (
  hash TEXT PRIMARY KEY CHECK(length(hash) = 64),
  revision INTEGER NOT NULL CHECK(revision > 0),
  body TEXT NOT NULL CHECK(json_valid(body))
);
