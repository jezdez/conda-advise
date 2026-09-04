# conda-advise

`conda-advise` checks public conda-forge package records for matching security advisories.
It adds a manual `conda advise` command and a warning-only check between solving and installation.

:::{warning}
This is alpha software with no published package release.
Use the [source installation](how-to/install.md) without changing a normal conda installation.
:::

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

The default `osv` provider maps an exact conda artifact to Python components through Parselmouth and queries those components through OSV.
The experimental `basilisk` provider sends public conda-forge package names and versions to Prefix.

An advisory match is a reason to investigate the exact package build.
It does not prove that vulnerable code is reachable or remains unpatched.
Missing mappings and empty results do not prove that a package is unaffected.

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

Only recognized public conda-forge records are eligible for network lookup.
The default provider sends artifact SHA-256 values to Prefix's Parselmouth service, then sends discovered PyPI component names and versions to OSV.
The optional Basilisk provider sends conda-forge package names and versions to Prefix.

Private channels, defaults, Anaconda commercial channels, local channels, and unrecognized mirrors are not queried.
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
