# Matching and evidence

`conda-advise` reports candidates for investigation.
It does not make a final statement about exploitability or the security of an environment.

## Exact artifact subjects

A conda package name and upstream version can have multiple builds for different platforms, dependency constraints, compilers, and patch sets.
The report therefore keeps the package name, version, build string, subdir, archive filename, channel identity, and SHA-256 together as one subject.

This uses the same package-record inputs as [conda-sboms](https://github.com/conda-incubator/conda-sboms).

## Artifact-component evidence

The default provider asks [Parselmouth](https://github.com/prefix-dev/parselmouth) which Python distributions it associates with an exact conda archive.
Each returned component is tied to the artifact SHA-256 and represented by a PyPI package URL.

This follows the distinction documented in [purl-associator PR #279](https://github.com/prefix-dev/purl-associator/pull/279).
A vendored Python distribution is a component of the conda artifact, not another identity for the conda package.

The evidence value is `artifact_component`.
It establishes that Parselmouth associated the component with that archive and that [OSV](https://osv.dev/) matched the component version.
It does not establish that the vulnerable function is shipped, reachable, enabled, or unpatched by the conda recipe.

## Upstream-version evidence

[Basilisk](https://basilisk.prefix.dev/status) accepts conda-forge package names and versions and joins them to upstream identifiers and vulnerability data.
The evidence value is `upstream_version`.

This match can cover packages that have no Parselmouth component mapping.
It is less specific than an artifact-component match because the exact conda build may contain patches or differ from the upstream release.

## Advisory identity and severity

Records are merged only when they have an identical advisory ID or are connected through OSV `aliases`.
OSV `related` and `upstream` links do not merge findings.

The display identifier prefers CVE, then GHSA, then the provider-native identifier.
Every retained active source record and alias remains available in JSON.
Advisory details with a nonempty `withdrawn` value are excluded before findings are built.

OSV commonly supplies CVSS vectors rather than scores.
`conda-advise` calculates their scores with the [`cvss` Python package](https://github.com/RedHatProductSecurity/cvss) and retains the original vectors.
Each vector's CVSS version determines its severity band.
When valid vectors are present, the highest severity controls filtering, while the displayed score is the highest numeric score.
Otherwise the client falls back to recognized provider severity labels.
Membership in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) always meets the warning threshold.

## Fix versions

Fix versions are copied from the advisory source and describe the affected upstream ecosystem.
They are not conda package recommendations and may not correspond to an available conda-forge build.
Use conda's normal solver and inspect the recipe and build history before changing an environment.
