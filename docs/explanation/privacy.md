# Privacy

Provider lookup can disclose that a machine is evaluating a package or component.
`conda-advise` limits what it sends and rejects package records outside its public conda-forge scope.

## Eligible records

The default allowed origins are:

- `https://conda.anaconda.org/conda-forge`, including conda-forge label paths
- `https://prefix.dev/conda-forge`

A trusted mirror can be added explicitly.
Private channels, defaults, Anaconda commercial channels, local files, and unrecognized mirrors remain `not_checked`.

Credentials, Anaconda token path segments, query strings, and fragments are stripped before URLs are cached or displayed.
Those artifact URL values are not included in provider paths or bodies.
Conda can separately authenticate a configured endpoint as described below.

The local JSON report includes exact credential-free subjects, including records with `not_checked` coverage.
A private or unrecognized subject can therefore retain its sanitized origin URL in local output.
Its identity and URL are never transmitted to a public provider or stored as provider query input.

## Metadata shared by every request

Every online lookup uses conda's `get_session()` interface.
The destination service receives the request method, host, path, query size, timing, and the source address presented by the network connection.
Conda sets the `User-Agent` header from its active context, which can identify the conda, Requests, Python, operating-system, solver, and related plugin versions.
Requests also supplies normal HTTP headers such as `Host`, `Accept`, `Accept-Encoding`, and `Connection`.
JSON posts include `Content-Type: application/json` and their encoded content length.
Conda session-header and request-header plugins can add permitted headers for a matching host and path.
Cookies set by an endpoint can be returned on a later request that reuses its conda session.
Retries can expose repeated copies of the same request.

Conda applies configured proxy, certificate, TLS verification, and authentication settings to these requests.
An HTTPS proxy normally sees the destination host, connection metadata, and transfer size.
A proxy that terminates TLS sees the complete path, headers, and body.
The service or TLS-terminating proxy sees any configured client certificate identity.

Endpoint URLs are sanitized before use, so embedded user information, Anaconda token path segments, query strings, and fragments in an endpoint setting are removed.
Other conda authentication can still apply to that sanitized endpoint.
A matching conda channel auth handler, `.netrc` entry, stored Anaconda token, proxy credential, or request-header plugin can transmit credentials or identifying headers such as `Authorization` or `Proxy-Authorization`.
Review these settings before pointing `conda-advise` at a public or self-hosted endpoint.

## `osv` provider

An online `osv` scan can make the following requests.

### Parselmouth component discovery

For each unique eligible artifact hash that is not satisfied by the cache, the client sends `GET /hash-v0/{sha256}` to the configured Parselmouth endpoint, which defaults to `conda-mapping.prefix.dev`.
The path contains the artifact's complete 64-character SHA-256 digest and the request has no application body.
The client does not place the package name, version, build, subdir, channel URL, prefix path, or MD5 in this request.
Parselmouth can resolve the hash to an artifact and can therefore derive package identity from its own data.

### OSV matching

The client sends one or more `POST /v1/querybatch` requests to the configured OSV endpoint, which defaults to `api.osv.dev`, with at most 1,000 unique component queries per request.
Each JSON body has one top-level `queries` array.
Each initial query contains `package.ecosystem` with the constant value `PyPI`, `package.name` with the normalized component name returned by Parselmouth, and `version` with the exact component version returned by Parselmouth.
The local component PURL is not sent to OSV.
When OSV returns `next_page_token` for a query, the next batch body repeats that query and adds `page_token` with the opaque value returned by OSV.

For every matched advisory body not satisfied by the cache, the client sends `GET /v1/vulns/{advisory_id}` to the same endpoint.
The path contains the percent-encoded advisory ID returned by the batch response and has no application body.
The returned advisory modification time is part of the local cache key but is not sent in the detail path.

### CISA KEV enrichment

When a provider returned at least one finding with a CVE identifier or alias and the KEV cache needs refreshing, the client sends a bodyless `GET` for the configured CISA KEV catalog URL.
It does not send a package, component, advisory, or CVE identifier to CISA.
The timing of a refresh can still reveal that the scan produced at least one provider finding with a CVE identifier or alias.

## `basilisk` provider

The client sends one or more `POST /v1/querybatch` requests to the configured Basilisk endpoint, which defaults to `api.basilisk.prefix.dev`, with at most 1,000 unique package queries per request.
Each JSON body has one top-level `queries` array.
Each query contains only `package.purl`.
The PURL fields are the constant type `conda`, the constant namespace `conda-forge`, the canonical public conda-forge package name, and its version.
The PURL has no qualifiers or subpath, so it does not contain the build string, build number, subdir, artifact filename, SHA-256, MD5, or channel URL.

For every matched advisory body not satisfied by the cache, the client sends `GET /v1/vulns/{advisory_id}` to the same endpoint.
The path contains the percent-encoded advisory ID returned by Basilisk and has no application body.
Basilisk pagination tokens are not accepted or retransmitted in v1.

Selecting `--provider=basilisk` opts into that transmission for one run.
Setting `plugins.conda_advise_provider` to `basilisk` enables it for manual scans and post-solve checks until configuration changes.

The client does not place local prefix paths or private records in Basilisk requests.
KEV enrichment uses the same CISA request described for the `osv` provider.

## Correlation and inventory disclosure

`conda-advise` never uploads one report object or one list that includes excluded records.
That does not make an online scan anonymous.

Parselmouth can correlate concurrently requested artifact hashes through source address, timing, conda metadata, configured credentials, and request headers.
OSV sees as many as 1,000 component names and versions together in a batch and then sees the advisory IDs requested for details.
Basilisk sees as many as 1,000 public conda-forge names and versions together in each batch and then sees the advisory IDs requested for details.
For a prefix with at most 1,000 unique eligible inputs, one batch can disclose the entire eligible component or package subset to that service.
Multiple batches, retries, detail requests, and KEV timing can be correlated into a larger partial inventory.

Only one provider runs for a scan.
An `osv` run sends hashes to Prefix's Parselmouth service and components to OSV, while a `basilisk` run sends conda PURLs to Prefix's Basilisk service and does not call Parselmouth or OSV.
Private and unrecognized subjects remain excluded from all provider paths and bodies.

## Local storage

The SQLite cache stores sanitized inputs for eligible provider requests, normalized responses, status, and timestamps.
It does not cache excluded private or unrecognized records as provider inputs and never stores conda credentials or unsanitized URLs.

Use `--offline` when no provider requests are acceptable.
The resulting report states which artifacts lacked usable cached coverage.
