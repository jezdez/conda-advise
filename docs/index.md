# conda-advise

`conda-advise` is a [conda](https://docs.conda.io/) plugin that checks an environment's package records for security advisories.
It uses Prefix's [Parselmouth](https://github.com/prefix-dev/parselmouth) mappings to identify PyPI components in conda artifacts, then queries [OSV](https://osv.dev/).
An experimental provider queries Prefix's [Basilisk](https://basilisk.prefix.dev/status) using conda package names and versions.

Run `conda advise` for a report.
By default, the plugin also warns about matching packages before conda changes an environment.

:::{warning}
This is alpha software with no published release yet.
Use the [source installation](how-to/install.md) to try it.
:::

## Try it

Clone the repository and create its locked [Pixi](https://pixi.prefix.dev/) development environment:

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

Scan the active or default environment:

```console
pixi run --locked -e dev conda advise
```

![conda advise quickstart](../demos/quickstart.gif)

The default threshold flags high and critical matches, plus matched CVEs in an available [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
Follow the [getting-started tutorial](tutorials/getting-started.md) to read the report and scan another environment.

## What a report tells you

The report lists advisory matches, their evidence, and coverage for each package record.
A match can identify a component associated with an exact artifact (`artifact_component`) or an upstream name and version (`upstream_version`).
Neither proves that vulnerable code is reachable or unpatched in the conda build.

An unmapped artifact is `not_checked` and a failed lookup is `incomplete`.
Neither state means unaffected.
A completed query with no match only describes that provider's data at that time.
See [matching and evidence](explanation/matching-and-evidence.md) and [limitations](explanation/limitations.md) before acting on a result.

## Data sent to advisory services

By default, only records with artifact URLs beneath the canonical conda-forge channel or Prefix mirror are eligible for lookup.
Records from private, defaults, commercial, local, or unrecognized channels remain `not_checked` when their URLs fall outside those origins.
Adding a trusted origin permits lookup of recognized records beneath it, including private records.

Online scans send artifact hashes to Parselmouth and component names and versions to OSV, or conda names and versions to Basilisk.
Requests use conda's network configuration.
See [privacy](explanation/privacy.md) for the exact requests and authentication behavior, or [run offline](how-to/use-offline.md).

## Before conda changes an environment

The default post-solve hook checks packages selected for linking, including during dry runs and `-y` transactions.
It adds severity tags and a warning without another prompt.
Provider failures leave coverage incomplete and let conda continue.
Use the [configuration guide](how-to/configure-post-solve.md) to change its threshold, deadline, or warning mode.

![conda post-solve advisory warning](../demos/post-solve-warning.gif)

## Documentation

::::{grid} 2
:gutter: 3

:::{grid-item-card} {octicon}`rocket` Tutorial
:link: tutorials/getting-started
:link-type: doc

Run a scan and read its findings and coverage.
:::

:::{grid-item-card} {octicon}`tools` How-to guides
:link: how-to/install
:link-type: doc

Install, configure warnings, run offline, or use CI.
:::

:::{grid-item-card} {octicon}`list-unordered` Reference
:link: reference/cli
:link-type: doc

Commands, settings, JSON fields, providers, and reason codes.
:::

:::{grid-item-card} {octicon}`code` Python API
:link: reference/python-api
:link-type: doc

Use the report and evidence models from Python.
:::

:::{grid-item-card} {octicon}`book` Explanation
:link: explanation/matching-and-evidence
:link-type: doc

Matching, privacy, caching, and coverage limits.
:::

:::{grid-item-card} {octicon}`link` Related tools
:link: explanation/ecosystem-comparison
:link-type: doc

conda-sboms, conda-sigstore, OSV-Scanner, Grype, and Anaconda.
:::

::::

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
