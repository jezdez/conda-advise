# Scan without network access

Use `--offline` to prevent a manual scan from scheduling network requests:

```console
conda advise --prefix /path/to/environment --offline
```

The command may use cached positive matches that are no more than seven days old.
Those matches are marked stale when their normal 24-hour freshness period has expired.
Expired empty results are not reused.

Eligible artifacts without usable cached provider data are `incomplete` with reason `offline_cache_miss`, and the command exits with status 2.
Ineligible records, records without the SHA-256 required by the `osv` provider, and artifacts already mapped as containing no supported component remain `not_checked`.
The report does not interpret either status as unaffected.

Request structured output for offline automation:

```console
conda advise --prefix /path/to/environment --offline --json > advise-report.json
```

Do not combine `--offline` and `--refresh`.
Refreshing requires network access and the command rejects that combination as a usage error.

Conda's global offline setting is also respected because all requests use conda's own session interface.
