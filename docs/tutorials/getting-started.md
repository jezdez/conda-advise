# Check an environment for advisories

Security advisories name upstream projects, but a conda environment contains exact package builds that may include patches and vendored components.
This tutorial runs `conda-advise` from its locked source checkout, scans the development environment, and shows how to distinguish a finding from coverage that remains unknown.

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
The command reads installed conda package records and schedules provider requests only for eligible public conda-forge records.

The default lookup follows this path:

```text
artifact SHA-256 → Prefix Parselmouth → PyPI component name and version → OSV
```

The SHA-256 identifies the exact conda archive.
Parselmouth returns Python distributions associated with that archive, and OSV evaluates each returned name and exact version.
The resulting `artifact_component` evidence connects the advisory match to a component of the archive without claiming that vulnerable code is reachable or unpatched.

## Read the report

The deterministic demonstration uses fixed advisory data and produces the following report when redirected or shown without color.
Only the temporary target directory changes between runs.

```text
Conda advisory report
Target:    <temporary-directory>/prefix
Provider:  osv

Advisory matches

demo-package 1.0.0 py_0 (conda-forge/noarch)
└── CVE-2026-0001 [critical, CVSS 9.8, CISA KEV]
    ├── Summary: Demo package accepts an unsafe example input
    ├── Aliases: GHSA-demo-0001-0001
    ├── Upstream fixes: 1.0.1
    ├── Evidence: artifact component pkg:pypi/demo-package@1.0.0
    └── Sources: osv:GHSA-demo-0001-0001
        http://127.0.0.1:8765/v1/vulns/GHSA-demo-0001-0001

Scan summary
Checked 1 of 1 artifacts.
Mapped 1, unmapped 0, not checked 0, incomplete 0.
Found 1 match, 1 at or above high or listed in CISA KEV.
```

The package heading records the conda name, version, build, channel, and platform directory.
The advisory line gives its preferred identifier, normalized severity, highest numeric Common Vulnerability Scoring System (CVSS) score, and KEV status.
`CISA KEV` means the CVE appears in CISA's catalog of vulnerabilities known to have been exploited in the wild.
The evidence line names the PyPI component associated with the exact archive.
The upstream fix is information from the advisory source, not a promise that the named version is available as a conda-forge package.

An interactive terminal adds Rich styling, while written severity and status labels carry the meaning when color is unavailable or output is redirected.

The summary separately counts:

- checked artifacts
- artifacts mapped to components
- unmapped artifacts
- incomplete lookups
- total matches
- matches that meet the configured severity threshold

An unmapped artifact is reported as `not_checked`.
It is not a claim that the artifact has no known vulnerabilities.

A failed attempted lookup is `incomplete`.
A completed lookup with no finding means only that the provider returned no match for those inputs at that time.

## Understand the post-solve warning

The plugin's default configuration also checks the packages that conda plans to link after a solve.
Qualifying matches receive one highest-severity tag in the transaction display, followed by a concise diagnostic that directs you to `conda advise` for details.

![post-solve advisory warning](../../demos/post-solve-warning.gif)

The hook runs during dry runs and commands using `-y`.
It does not add another prompt, block the transaction, or turn a provider failure into a conda failure.
Use the [post-solve configuration guide](../how-to/configure-post-solve.md) to change the warning threshold or disable automatic checks.

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

More precisely, each eligible package contributes one conda package URL containing only the constant `conda` type, the constant `conda-forge` namespace, the canonical package name, and its version.
It does not call Parselmouth or OSV from your machine.

Both providers download the CISA KEV catalog only after a result contains a CVE identifier or alias.
That download sends no package, component, advisory, or CVE identifier to CISA.

## Next steps

- Read [matching and evidence](../explanation/matching-and-evidence.md) before acting on a finding.
- Configure [post-solve warnings](../how-to/configure-post-solve.md).
- Use the [CI guide](../how-to/use-in-ci.md) with the documented exit codes.
- Review [privacy](../explanation/privacy.md) before enabling Basilisk persistently.
