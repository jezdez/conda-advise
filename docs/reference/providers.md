# Provider reference

One provider runs per scan.
CISA KEV is shared enrichment and is not a provider.
The default allowed-origin list contains the canonical conda-forge and Prefix mirror URL prefixes.
Adding an origin authorizes recognized records below that URL path for provider lookup, including private records if the configured path contains them.

## `osv`

Status
: Default

Input selection
: Records that carry SHA-256 and whose sanitized artifact URLs match the configured allowed-origin list

Requests
: Artifact SHA-256 to Parselmouth, then normalized PyPI component name and exact version to OSV

Evidence
: `artifact_component`

The Parselmouth response associates Python distributions as components of the exact conda artifact.
The OSV query determines whether the reported component name and version match an advisory's affected-version ranges.

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

The Basilisk service joins conda package identities to vulnerability sources and evaluates upstream version matches.
`conda-advise` does not treat that result as an exact conda-build assessment.

The service source, result-data license, API stability, and mirroring terms are not documented for third-party reliance.
The provider therefore remains experimental and requires an explicit CLI selection or persistent configuration.

## KEV enrichment

The [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) records CVEs known to have been exploited in the wild.
`conda-advise` joins KEV entries only to CVE aliases already matched by the selected provider.

KEV can raise a matched finding's priority.
It never creates package applicability by itself.
