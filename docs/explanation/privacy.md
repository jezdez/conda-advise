# Privacy

Provider lookup can disclose that a machine is evaluating a package or component.
Only records whose sanitized artifact URLs match the configured allowed origins are eligible for provider lookup.

## Eligible records

The default allowed origins are:

- `https://conda.anaconda.org/conda-forge`, including conda-forge label paths
- `https://prefix.dev/conda-forge`

You can [add a trusted mirror](../how-to/allow-trusted-mirrors.md).
With the defaults, ordinary records from private channels, defaults, Anaconda commercial channels, local files, and unrecognized mirrors have other URLs and remain `not_checked`.
Adding an origin permits provider lookup for recognized records beneath it, including private records.
Recognition checks the syntax of the package name and version and requires a known conda subdirectory.
The client does not verify the record's channel field, filename, or digest against conda-forge metadata.
An allowed-looking URL can make a record eligible regardless of those fields.

Credentials, Anaconda token path segments, query strings, and fragments are stripped before URLs are cached or displayed.
Those artifact URL values are not included in provider paths or bodies.
conda can separately authenticate a configured endpoint as described below.

The local JSON report includes credential-free identities and sanitized origins for all subjects, including excluded records.
Excluded identities are neither sent to providers nor cached as provider query input.

## Metadata shared by every request

Every online lookup uses conda's [`get_session()`](https://docs.conda.io/projects/conda/en/stable/dev-guide/api/conda/gateways/connection/session/index.html) interface.
The destination service receives the request method, host, path, request body size, timing, and the source address presented by the network connection.
conda sets the `User-Agent` header from its active context.
It includes the conda and Requests versions, Python implementation and version, platform system and release, operating-system distribution and version, libc when known, and the selected non-classic solver's user-agent string.
Requests also supplies normal HTTP headers such as `Host`, `Accept`, and `Connection`.
The client requests `Accept-Encoding: identity` and rejects compressed responses.
JSON posts include `Content-Type: application/json` and their encoded content length.
On conda versions that provide them, session-header and request-header plugins can add permitted headers for a matching host and path.
Cookies set by an endpoint can be returned on a later request that reuses its conda session.
Retries can expose repeated copies of the same request.

conda applies configured proxy, certificate, TLS verification, and authentication settings to these requests.
An HTTPS proxy normally sees the destination host, connection metadata, and transfer size.
A proxy that terminates TLS sees the complete path, headers, and body.
The service or TLS-terminating proxy sees any configured client certificate identity.

Endpoint settings reject embedded user information, query strings, and fragments.
At runtime, endpoint URLs are sanitized again and Anaconda `/t/<token>` path segments are removed before the request.
Other conda authentication can still apply to that sanitized endpoint.
A matching conda channel auth handler, `.netrc` entry, stored Anaconda token, or request-header plugin can add credentials or identifying headers.
Credentials in configured proxy URLs still apply to the proxy connection.
Redirects and HTTP 407 responses fail before conda's authentication response hooks run, preventing interactive proxy prompts or forwarding proxy credentials to an advisory endpoint.
Review these settings before pointing `conda-advise` at a public or self-hosted endpoint.

HTTP requests run in separate processes that copy the active conda settings and installed plugin selection.
An in-memory plugin that cannot be recreated there causes an incomplete request failure.
The client does not silently omit that plugin's authentication.

## `osv` provider

An online `osv` scan can make the following requests.

### Parselmouth component discovery

For each eligible artifact hash missing from the cache, the client sends `GET /hash-v0/{sha256}` to the configured [Parselmouth](https://github.com/prefix-dev/parselmouth) endpoint, which defaults to `conda-mapping.prefix.dev`.
The path contains the artifact's complete 64-character SHA-256 digest and the request has no application body.
The client does not place the package name, version, build, subdir, channel URL, prefix path, or MD5 in this request.
Parselmouth can resolve the hash to an artifact and can therefore derive package identity from its own data.

### OSV matching

The client sends `POST /v1/querybatch` to the configured [OSV](https://osv.dev/) endpoint, which defaults to `api.osv.dev`, with at most 1,000 unique component queries per request.
Each JSON body has one top-level `queries` array.
Each initial query contains `package.ecosystem` with the constant value `PyPI`, `package.name` with the normalized component name returned by Parselmouth, and `version` with the exact component version returned by Parselmouth.
The local component PURL is not sent to OSV.
When OSV returns `next_page_token` for a query, the next batch body repeats that query and adds `page_token` with the opaque value returned by OSV.

For every query match whose valid detail is not satisfied by the cache, the client sends `GET /v1/vulns/{advisory_id}` to the same endpoint.
The path contains the percent-encoded advisory ID returned by the batch response and has no application body.
The advisory modification time is part of the local cache key but is not sent in the detail path.

### CISA KEV enrichment

When a non-withdrawn provider finding has a CVE identifier or alias, KEV enrichment first uses an eligible fresh cached catalog unless `--refresh` was requested.
Otherwise an online scan attempts a bodyless `GET` for the built-in [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) URL.
If that request fails, an eligible cached positive catalog may be used as stale and the scan is marked incomplete.
Offline scans never send this request.
It does not send a package, component, advisory, or CVE identifier to CISA.
The timing of a refresh can still reveal that the scan produced at least one provider finding with a CVE identifier or alias.

## `basilisk` provider

The client sends `POST /v1/querybatch` to the configured [Basilisk](https://basilisk.prefix.dev/status) endpoint, which defaults to `api.basilisk.prefix.dev`, with at most 1,000 unique package queries per request.
Each JSON body has one top-level `queries` array.
Each query contains only `package.purl`.
The PURL fields are the constant type `conda`, the constant namespace `conda-forge`, the canonical package name derived from the eligible record, and its version.
The PURL has no qualifiers or subpath, so it does not contain the build string, build number, subdir, artifact filename, SHA-256, MD5, or channel URL.

During an online scan, every query match whose valid detail is not satisfied by the cache produces `GET /v1/vulns/{advisory_id}` to the same endpoint.
The path contains the percent-encoded advisory ID returned by Basilisk and has no application body.
Basilisk pagination tokens are not accepted or retransmitted in v1.

Selecting `--provider=basilisk` opts into that transmission for one run.
Setting `plugins.conda_advise_provider` to `basilisk` enables it for manual scans and post-solve checks until configuration changes.

Basilisk requests omit local prefix paths and excluded records.
KEV enrichment uses the same CISA request described for the `osv` provider.

## Correlation and inventory disclosure

Services can correlate requests into a partial package inventory.

Parselmouth can correlate concurrently requested artifact hashes through source address, timing, conda metadata, configured credentials, and request headers.
OSV sees as many as 1,000 component names and versions together in a batch and then sees the advisory IDs requested for details.
Basilisk sees as many as 1,000 eligible package names and versions together in each batch and then sees the advisory IDs requested for details.
For a prefix with at most 1,000 unique eligible inputs, one batch can disclose the entire eligible component or package subset to that service.
Multiple batches, retries, detail requests, and KEV timing can be correlated into a larger partial inventory.

Only one provider runs for a scan.
An `osv` run sends hashes to Prefix's Parselmouth service and components to OSV, while a `basilisk` run sends conda PURLs to Prefix's Basilisk service and does not call Parselmouth or OSV.
Excluded records never appear in provider paths or bodies.

## Local storage

The [SQLite cache](cache-and-freshness.md) stores eligible sanitized request inputs, validated provider data, status, and timestamps.
It omits excluded provider inputs, conda credentials, and unsanitized URLs.

Use `--offline` when no provider requests are acceptable.
The resulting report states which artifacts lacked usable cached coverage.
