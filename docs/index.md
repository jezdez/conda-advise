# conda-advise

Security advisories usually identify upstream projects and versions, while conda installs exact artifacts that can contain patches or vendored components.
That makes a direct name match weak evidence and makes an absent match easy to misread.

With its default allowed-origin list, `conda-advise` checks package records whose sanitized artifact URLs match the canonical conda-forge or Prefix mirror URL prefixes, preserves the reported artifact identity, and tells you what evidence produced each advisory match.
Run `conda advise` to inspect an environment now.
The warning-only post-solve hook also calls attention to matching packages after a solve and before installation.

:::{warning}
This is alpha software with no published package release.
Use the [source installation](how-to/install.md) without changing a normal conda installation.
:::

## What it does and does not do

`conda-advise` reads installed conda package records from one prefix and reports advisory candidates together with per-artifact coverage.
The default `osv` provider maps exact artifact hashes to PyPI components before querying OSV.
The experimental `basilisk` provider instead sends names and versions from eligible records to Prefix.

It does not scan arbitrary files or unmanaged pip installations, prove that vulnerable code is present or reachable, remediate packages, or establish that an environment is safe.
Records whose sanitized artifact URLs do not match the configured allowed-origin list are read locally so they can be reported as `not_checked`, but they are not sent to a provider.
Adding an origin authorizes recognized records under that URL path for provider lookup, including private records if the configured path contains them.
Eligibility also requires syntactically valid package names, versions, and conda subdirectories, but the client does not cross-check the record's channel field, filename, or digest against conda-forge metadata.
Online scans use conda's network session and can therefore send normal HTTP metadata and configured authentication to the selected service.

Clone the repository and create its locked development environment:

::::{tab-set}

:::{tab-item} POSIX

```console
git clone https://github.com/jezdez/conda-advise.git
cd conda-advise
pixi install --locked -e dev
```

:::

:::{tab-item} PowerShell

```powershell
git clone https://github.com/jezdez/conda-advise.git
Set-Location conda-advise
pixi install --locked -e dev
```

:::

::::

Run the first scan from that checkout:

```console
pixi run --locked -e dev conda advise
```

![conda advise quickstart](../demos/quickstart.gif)

With no target option, the command scans the active or default environment.
The default threshold flags high and critical matches.
When a valid current or permitted stale [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is available to the scan, every matched CVE listed there also qualifies regardless of severity.

## From package record to evidence

```text
eligible package record by sanitized artifact URL
├── osv, default
│   └── artifact SHA-256 → Parselmouth → PyPI name and version → OSV
│       └── artifact_component evidence
└── basilisk, experimental
    └── name and version in a conda-forge PURL → Prefix Basilisk
        └── upstream_version evidence
```

The default path sends an artifact SHA-256 to Prefix's Parselmouth service, then sends the normalized PyPI component name and exact version returned by Parselmouth to OSV.
`artifact_component` means that the component was associated with the exact archive and its version matched an OSV advisory.

Each unique eligible package name and version contributes one conda package URL to the opt-in Basilisk path.
That URL contains the constant `conda` type, the constant `conda-forge` namespace, the canonical package name, and its version.
`upstream_version` means Basilisk matched that name and version, not the exact conda build.

An advisory match is a reason to investigate the exact package build.
It does not prove that vulnerable code is reachable or remains unpatched.
An unmapped package is `not_checked`, a failed attempted lookup is `incomplete`, and neither state means unaffected.
A completed provider query with no match is only a statement about that provider's inputs and data at that time.

## Before conda changes an environment

The post-solve hook checks only packages selected for linking.
It runs synchronously after solving and before conda creates the transaction, so cache and provider work can delay the command until the configured deadline.
The deadline stops the scan from waiting for unfinished requests and marks their work incomplete.
It does not terminate an HTTP worker that is already running, which may finish after the report but cannot change it.
It adds a severity tag to matching transaction records and prints a concise warning without adding a prompt.
Ordinary scan exceptions are caught, so normal provider failures do not abort the transaction.

![conda post-solve advisory warning](../demos/post-solve-warning.gif)

## Choose a documentation path

::::{grid} 2
:gutter: 3

:::{grid-item-card} {octicon}`rocket` Tutorial
:link: tutorials/getting-started
:link-type: doc

Run a first scan and interpret its coverage and findings.
:::

:::{grid-item-card} {octicon}`tools` How-to guides
:link: how-to/install
:link-type: doc

Install from source, configure warnings, run offline, use CI, and trust a mirror.
:::

:::{grid-item-card} {octicon}`list-unordered` Reference
:link: reference/cli
:link-type: doc

Look up commands, settings, JSON fields, providers, and coverage reason codes.
:::

:::{grid-item-card} {octicon}`code` Python API
:link: reference/python-api
:link-type: doc

Use the public report, subject, coverage, finding, evidence, and failure models.
:::

:::{grid-item-card} {octicon}`book` Explanation
:link: explanation/matching-and-evidence
:link-type: doc

Understand matching evidence, privacy, caching, limits, and related tools.
:::

::::

## What leaves the machine

With the default allowed-origin list, only recognized records whose sanitized artifact URLs match the canonical conda-forge or Prefix mirror URL prefixes are eligible for network lookup.
Ordinary records from private channels, defaults, Anaconda commercial channels, local channels, and unrecognized mirrors have other URLs, so they remain `not_checked` and are not sent.
Adding an origin makes recognized records below that URL path eligible, including private records if the configured path contains them.
The origin check does not independently verify the record's channel field, filename, or digest.
When a non-withdrawn provider finding has a CVE identifier or alias, the client first uses an eligible cached KEV catalog unless `--refresh` was requested.
Otherwise an online scan attempts to download the CISA KEV catalog without sending a package, component, advisory, or CVE identifier to CISA.
If that request cannot complete, an eligible cached positive catalog may be used as stale and the scan is marked incomplete.
Offline scans never send the request.
Read the complete [privacy behavior](explanation/privacy.md) before enabling a provider in an automated environment.

```{toctree}
:hidden:
:caption: Tutorial

tutorials/getting-started
```

```{toctree}
:hidden:
:caption: How-to guides

how-to/install
how-to/configure-post-solve
how-to/choose-provider
how-to/use-offline
how-to/use-in-ci
how-to/allow-trusted-mirrors
```

```{toctree}
:hidden:
:caption: Reference

reference/cli
reference/configuration
reference/json-output
reference/providers
reference/coverage-and-reason-codes
reference/python-api
```

```{toctree}
:hidden:
:caption: Explanation

explanation/matching-and-evidence
explanation/privacy
explanation/cache-and-freshness
explanation/limitations
explanation/ecosystem-comparison
```

```{toctree}
:hidden:
:caption: Project

changelog
```
