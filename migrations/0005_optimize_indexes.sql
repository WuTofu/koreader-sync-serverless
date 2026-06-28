-- Drop redundant indexes: UNIQUE constraints already create implicit indexes on these columns,
-- so these named indexes duplicate that work and add unnecessary write amplification.
DROP INDEX IF EXISTS idx_sessions_token_hash;
DROP INDEX IF EXISTS idx_admin_sessions_token_hash;

-- Drop secondary progress indexes: they only served infrequent web-console reads
-- (listProgressRecordsByUser, getProgressSummaryByUser, listDeviceUsageByUser) while
-- adding ~2 extra rows written on every KOReader sync. Each user has few progress rows
-- (one per document via UNIQUE), so console queries scan cheaply without these indexes.
DROP INDEX IF EXISTS idx_progress_user_timestamp;
DROP INDEX IF EXISTS idx_progress_user_device;
