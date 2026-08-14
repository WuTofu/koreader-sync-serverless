-- progress.id was INTEGER PRIMARY KEY AUTOINCREMENT, which forces SQLite to maintain a
-- counter row in the unindexed sqlite_sequence table. Every insert linearly scans that
-- table and writes it back BEFORE the UNIQUE(user_id, document) conflict is detected, so
-- each KOReader sync paid ~5 extra rows read + 1 row written even when nothing changed
-- (measured via wrangler d1 insights: avgRowsRead=6, avgRowsWritten=1 per upsert call,
-- including fully idempotent no-op re-syncs). Nothing reads or references progress.id
-- (no SELECT, no foreign key, no API response), so a plain INTEGER PRIMARY KEY — still a
-- unique auto-assigning rowid, just without the sqlite_sequence bookkeeping — is equivalent.
CREATE TABLE progress_new (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  document TEXT NOT NULL,
  progress TEXT NOT NULL,
  percentage REAL NOT NULL,
  device TEXT NOT NULL,
  device_id TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE (user_id, document)
);

INSERT INTO progress_new (id, user_id, document, progress, percentage, device, device_id, timestamp, updated_at)
  SELECT id, user_id, document, progress, percentage, device, device_id, timestamp, updated_at FROM progress;

DROP TABLE progress;

ALTER TABLE progress_new RENAME TO progress;
