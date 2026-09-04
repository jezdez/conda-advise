# Limitations

`conda-advise` narrows public vulnerability data to candidates related to public conda-forge packages.
Several facts needed for an exact package assessment are not available in the current public data.

## Package contents and patches

Parselmouth reports Python distributions found inside an artifact.
It does not establish which modules, functions, optional features, or vulnerable code paths remain in that archive.

Basilisk matches upstream identities and versions.
A conda build may carry backported patches without changing its upstream version.

Neither evidence type replaces recipe inspection, artifact analysis, a package-specific SBOM, or VEX supplied by a responsible maintainer.

## Ecosystem coverage

The default provider checks only PyPI components returned by Parselmouth.
Native libraries, statically linked dependencies, vendored non-Python projects, operating-system packages, and unmanaged pip packages may be absent.

OSV does not define a general `Conda` ecosystem query that can replace component discovery.
An empty conda package-URL response is therefore not treated as coverage.

## Provider availability

Parselmouth and Basilisk are hosted by Prefix.
OSV and CISA operate separate public services.
Network failures, rate controls, schema changes, stale caches, and missing mappings can leave a scan incomplete.

The post-solve hook always fails open.
It warns when it has qualifying evidence and never blocks a transaction.

## Severity and remediation

CVSS describes characteristics of a vulnerability, not the importance of one package in a specific deployment.
CISA KEV records exploitation in the wild but does not prove applicability to a conda artifact.

Fix versions come from upstream advisory records.
`conda-advise` does not solve, upgrade, remove, quarantine, or remediate packages.

## Windows ARM64 validation

The native Windows 11 ARM64 CI canary builds and installs the wheel from a locked conda-free Pixi environment, then imports conda-independent report models.
The full suite uses a `win-64` Pixi environment through Windows Prism because conda is not available from the ordinary conda-forge `win-arm64` subdir.
Native conda plugin discovery and transactions on Windows ARM64 are therefore not covered.
