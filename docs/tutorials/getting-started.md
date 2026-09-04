# Check an environment for advisories

This tutorial runs `conda-advise` from its locked source checkout, scans the development environment with the default provider, and explains how to read the report.

## Prerequisites

- Git
- [Pixi](https://pixi.prefix.dev/)
- Network access to Prefix's Parselmouth service, OSV, and CISA

`conda-advise` has no published release yet.
The source workflow keeps the preview inside the repository's Pixi environment.

## Start the development environment

::::{tab-set}

:::{tab-item} POSIX

```console
git clone https://github.com/jezdez/conda-advise.git
cd conda-advise
pixi install --locked -e dev
pixi run --locked -e dev conda advise --help
```

:::

:::{tab-item} PowerShell

```powershell
git clone https://github.com/jezdez/conda-advise.git
Set-Location conda-advise
pixi install --locked -e dev
pixi run --locked -e dev conda advise --help
```

:::

::::

The help output should identify the `osv` provider as the default and mark `basilisk` experimental.

## Run the first scan

```console
pixi run --locked -e dev conda advise
```

With no `--name` or `--prefix`, conda selects its active or default prefix.
The command reads installed conda package records and sends only eligible public conda-forge records to the selected provider.

A human report groups matches by exact conda artifact.
Each finding identifies the advisory, severity, evidence type, relevant component when known, fix versions reported by the advisory source, KEV status, and data freshness.

The summary separately counts:

- checked artifacts
- artifacts mapped to components
- unmapped artifacts
- incomplete lookups
- total matches
- matches that meet the configured severity threshold

An unmapped artifact is reported as `not_checked`.
It is not a claim that the artifact has no known vulnerabilities.

## Inspect the machine-readable report

Write one versioned JSON document to a file:

::::{tab-set}

:::{tab-item} POSIX

```console
pixi run --locked -e dev conda advise --json > advise-report.json
python -m json.tool advise-report.json | less
```

:::

:::{tab-item} PowerShell

```powershell
pixi run --locked -e dev conda advise --json | Set-Content advise-report.json
Get-Content advise-report.json | python -m json.tool
```

:::

::::

The document conforms to `conda-advise-report-v1`.
See the [JSON reference](../reference/json-output.md) for fields and exit behavior.

## Compare the experimental provider

Run a separate scan with Basilisk:

```console
pixi run --locked -e dev conda advise --provider=basilisk
```

This sends eligible public conda-forge package names and versions to Prefix.
It does not send private or unrecognized package records.
Basilisk results use `upstream_version` evidence because the match does not establish the status of one exact conda build.

## Next steps

- Read [matching and evidence](../explanation/matching-and-evidence.md) before acting on a finding.
- Configure [post-solve warnings](../how-to/configure-post-solve.md).
- Use the [CI guide](../how-to/use-in-ci.md) with the documented exit codes.
- Review [privacy](../explanation/privacy.md) before enabling Basilisk persistently.
