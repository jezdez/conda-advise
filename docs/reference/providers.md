# Provider reference

One provider runs per scan, with shared [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) enrichment.
Both providers use the [allowed-origin rules](../explanation/privacy.md), which default to the canonical conda-forge channel and Prefix mirror.

## `osv`

Status
: Default

Input selection
: Records that carry SHA-256 and whose sanitized artifact URLs match the configured allowed-origin list

Requests
: Artifact SHA-256 to [Parselmouth](https://github.com/prefix-dev/parselmouth), then normalized PyPI component name and exact version to [OSV](https://osv.dev/)

Evidence
: `artifact_component`

Parselmouth associates Python distributions with the exact conda artifact.
OSV checks their names and versions against advisory affected-version ranges.

OSV imports the [PyPA advisory database](https://github.com/pypa/advisory-database) and the other databases in its [source inventory](https://google.github.io/osv.dev/data/).
`conda-advise` does not query those imported sources separately.

A Parselmouth 404 means no component mapping was available.
It does not mean the artifact has no vulnerable component.

## `basilisk`

Status
: Experimental and opt-in

Input selection
: Package names and versions from recognized records whose sanitized artifact URLs match the configured allowed-origin list

Requests
: One or more requests to Prefix's [Basilisk API](https://api.basilisk.prefix.dev/openapi.json), with at most 1,000 unique conda PURL queries per batch

Evidence
: `upstream_version`

Prefix's [Basilisk](https://basilisk.prefix.dev/status) joins conda names and versions to upstream vulnerability data.
The result does not assess the exact conda build.
Select this provider explicitly with the CLI or [persistent configuration](../how-to/choose-provider.md).

## KEV enrichment

The [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) records CVEs known to have been exploited in the wild.
`conda-advise` joins KEV entries only to CVE aliases already matched by the selected provider.

KEV membership makes an existing match qualify regardless of severity.
It does not establish whether a CVE affects a package.

## Response limits

The client limits provider work to keep malformed or unusually large responses from exhausting scan resources:

| Data | Limit |
| --- | --- |
| Parselmouth components | 128 per artifact, 10,000 per scan |
| Advisory query pages | 10 per query |
| Advisory summaries | 1,000 per query, 10,000 per scan |
| Advisory details | 10,000 per scan |
| JSON response body | 16 MiB, uncompressed |
| Retained responses per request group | 64 MiB |

At most four HTTP request workers run at once.
Redirects, HTTP 407 responses, and compressed responses are rejected.
Active workers are terminated when the shared scan deadline expires.

Exceeding a limit produces incomplete coverage with `invalid_response`, or `deadline_exceeded` if the scan deadline has expired.
Truncated responses are not cached as complete results.
See [cache and freshness](../explanation/cache-and-freshness.md) for storage limits.
