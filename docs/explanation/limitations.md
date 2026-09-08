# Limitations

`conda-advise` checks package records against provider data.
It does not scan installed files or verify those records against conda-forge metadata.
See [privacy](privacy.md) for which records are eligible for lookup.

## Package contents and patches

[Parselmouth](https://github.com/prefix-dev/parselmouth) associates Python distributions with an artifact.
It does not establish which modules, functions, optional features, or vulnerable code paths remain in that archive.

[Basilisk](https://basilisk.prefix.dev/status) matches upstream identities and versions.
A conda build may carry backported patches without changing its upstream version.

Investigating a match may require recipe inspection, artifact analysis, or package-specific SBOM or VEX evidence.
[conda-sboms](https://github.com/conda-incubator/conda-sboms) provides package inventories and [conda-sigstore](https://github.com/jezdez/conda-sigstore) can verify signed attestations.
V1 does not consume those attestations.

## Ecosystem coverage

The default provider checks only PyPI components returned by Parselmouth.
Native libraries, statically linked dependencies, vendored non-Python projects, operating-system packages, and unmanaged pip packages may be absent.

The [OSV ecosystem list](https://osv.dev/) does not include a general `Conda` query that replaces component discovery.
An empty conda package-URL response is therefore not treated as coverage.

## Provider availability

Parselmouth and Basilisk are hosted by Prefix.
OSV and CISA operate separate public services.
Network failures, rate controls, schema changes, stale caches, and missing mappings can leave a scan incomplete.

The post-solve hook runs before conda creates the transaction and can delay the command until its scan deadline.
Provider failures leave coverage incomplete and let conda continue.
See [post-solve configuration](../how-to/configure-post-solve.md) for timing and warning behavior.

## Severity and remediation

CVSS describes characteristics of a vulnerability, not the importance of one package in a specific deployment.
CISA KEV records exploitation in the wild but does not prove applicability to a conda artifact.

Fix versions come from upstream advisory records.
`conda-advise` does not solve, upgrade, remove, quarantine, or remediate packages.

## Windows ARM64 validation

CI checks native wheel installation and model imports on Windows ARM64.
The full conda plugin suite runs through x64 emulation.
See [Windows installation notes](../how-to/install.md) for details.
