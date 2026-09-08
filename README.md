# conda-advise

`conda-advise` is a [conda](https://docs.conda.io/) plugin that checks an environment's package records for security advisories.
It uses Prefix's [Parselmouth](https://github.com/prefix-dev/parselmouth) mappings to identify PyPI components in conda artifacts, then queries [OSV](https://osv.dev/) for matching advisories.
An experimental provider queries Prefix's [Basilisk](https://basilisk.prefix.dev/status) using conda package names and versions.

Run `conda advise` for a report.
By default, the plugin also warns about matching packages before conda changes an environment.
Reports distinguish advisory matches from missing coverage, but do not establish whether vulnerable code is reachable or patched in a particular build.

This is alpha software with no published release yet.
Try it from the repository's locked development environment.

## Try it from source

Install [Pixi](https://pixi.prefix.dev/), clone the repository, and confirm that conda discovers the plugin:

```console
git clone https://github.com/jezdez/conda-advise.git
cd conda-advise
pixi install --locked -e dev
pixi run --locked -e dev conda advise --help
```

Scan the active or default environment:

```console
pixi run --locked -e dev conda advise
```

Scan another prefix and request versioned JSON output:

```console
pixi run --locked -e dev conda advise --prefix /path/to/environment --json
```

The default threshold flags high and critical matches, plus matched CVEs in an available [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

![Run a conda advise scan](https://raw.githubusercontent.com/jezdez/conda-advise/main/demos/quickstart.gif)

## How matching works

```text
eligible conda package record
├── osv, default
│   └── artifact SHA-256 → Parselmouth → PyPI name and version → OSV
│       └── artifact_component evidence
└── basilisk, experimental
    └── name and version in a conda-forge PURL → Prefix Basilisk
        └── upstream_version evidence
```

Only records with allowed artifact URLs are eligible for lookup.
The defaults cover the canonical conda-forge channel and Prefix mirror.
Records from other channels remain `not_checked`.
Adding a trusted origin also permits lookup of private records beneath that URL, so use a path that contains only packages you intend to identify publicly.
See [privacy](https://jezdez.github.io/conda-advise/explanation/privacy/) for the exact requests and conda's network settings.

## Interpret the result

An advisory match is a reason to inspect the exact conda build.
`artifact_component` associates a component with the archive, while `upstream_version` matches a package name and version.

An unmapped artifact is `not_checked` and a failed lookup is `incomplete`.
Neither state means unaffected, and a completed query with no match only describes that provider's data at that time.

## Post-solve warnings

The post-solve hook checks packages selected for linking, including during dry runs and `-y` transactions.
It adds severity tags and a warning without another prompt.
Provider failures leave coverage incomplete and let conda continue.
See [post-solve configuration](https://jezdez.github.io/conda-advise/how-to/configure-post-solve/) to change the threshold, deadline, or default warning mode.

![See a post-solve advisory warning](https://raw.githubusercontent.com/jezdez/conda-advise/main/demos/post-solve-warning.gif)

## Documentation

- [Getting started](https://jezdez.github.io/conda-advise/tutorials/getting-started/)
- [Installation](https://jezdez.github.io/conda-advise/how-to/install/)
- [CLI reference](https://jezdez.github.io/conda-advise/reference/cli/)
- [Provider behavior](https://jezdez.github.io/conda-advise/reference/providers/)
- [Evidence and result wording](https://jezdez.github.io/conda-advise/explanation/matching-and-evidence/)
- [Privacy](https://jezdez.github.io/conda-advise/explanation/privacy/)
- [Limitations](https://jezdez.github.io/conda-advise/explanation/limitations/)
- [Related tools](https://jezdez.github.io/conda-advise/explanation/ecosystem-comparison/), including [conda-sboms](https://github.com/conda-incubator/conda-sboms), [conda-sigstore](https://github.com/jezdez/conda-sigstore), [OSV-Scanner](https://google.github.io/osv-scanner/), and [Grype](https://oss.anchore.com/docs/guides/vulnerability/)

## Development

```console
pixi run --locked -e dev check
pixi run --locked -e test test
pixi run --locked -e docs docs
pixi run --locked -e docs docs-linkcheck
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and [SECURITY.md](SECURITY.md) for private vulnerability reporting.
`conda-advise` is licensed under the BSD 3-Clause License.
