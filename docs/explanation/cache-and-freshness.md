# Cache and freshness

The SQLite cache reuses provider results for repeated checks and [offline scans](../how-to/use-offline.md).
Set `CONDA_ADVISE_CACHE_PATH` to choose a cache file on any supported platform.

## Fresh entries

Provider query results are fresh for 24 hours.
A Parselmouth 404 is also cached for 24 hours to avoid repeating a lookup for an unmapped artifact.
OSV advisory bodies are keyed by advisory ID and modification time.

`--refresh` bypasses otherwise fresh query results and replaces each query's result set.
Replacement matters because withdrawn advisories may disappear from current OSV query results.

## Stale entries

A positive advisory match may be reused for at most seven days when a current lookup cannot complete.
The report marks it stale and retains the last successful check time.

An expired empty result is never reused.
A missing current result therefore becomes `not_checked` or `incomplete` instead of being reported as a current zero-match result.

## Concurrent conda processes

The database uses write-ahead logging and a busy timeout for concurrent access.
HTTP workers return results to the scan process, which writes the cache and report.
Unfinished workers are terminated at the scan deadline and cannot change a completed report.

If the database is corrupt, `conda-advise` replaces it and continues without cached evidence.
Corruption recovery renames the database and removes its write-ahead-log sidecars without a separate interprocess recovery lock.
Normal cache failures do not abort a post-solve transaction.

## Storage limits

The cache prunes expired entries and evicts the oldest entries to remain within these limits:

| Resource | Limit |
| --- | --- |
| Entry payload | 16 MiB |
| Sources, keys, and payloads combined | 64 MiB |
| Entry count | 10,000 |
| Database file | 128 MiB |

Evicted or oversized results are unavailable to later offline scans.
Incomplete provider responses are not cached as complete results.
Before writing, a write-ahead log larger than 16 MiB is checkpointed.
If it remains oversized, that cache write is skipped.
