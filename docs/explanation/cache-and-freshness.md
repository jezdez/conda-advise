# Cache and freshness

The post-solve hook has a short deadline, while provider data changes less frequently than conda transactions.
A process-safe SQLite cache keeps repeated checks fast and makes limited offline reporting possible.

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

The database uses write-ahead logging and a busy timeout.
Network workers return typed results to one coordinating thread, which performs cache writes and reporting.
Workers that finish after the scan deadline cannot alter the completed report.

If the database is corrupt, `conda-advise` replaces it and continues without cached evidence.
The post-solve hook still lets conda continue.
