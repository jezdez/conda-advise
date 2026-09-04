# conda-advise

`conda-advise` checks public conda-forge packages for matching security advisories.
It adds a manual `conda advise` command and a warning-only post-solve check before conda changes an environment.

The project is alpha software and has no published package release yet.
Run it from the repository's locked development environment without changing a normal conda installation.

## What it checks

The default `osv` provider looks up the Python distributions found inside an exact conda artifact by [Parselmouth](https://github.com/prefix-dev/parselmouth), then checks those component names and versions through [OSV](https://osv.dev/).
Matching CVE identifiers are enriched with the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

The experimental `basilisk` provider checks public conda-forge package names and versions through Prefix's [Basilisk API](https://api.basilisk.prefix.dev/openapi.json).
Selecting it sends those names and versions to Prefix.

These results are advisory matches, not proof that vulnerable code is reachable or remains unpatched in a conda build.
An unmapped package, an unavailable provider, stale data, or an empty result does not establish that a package is unaffected.

## Run from source

Install [Pixi](https://pixi.sh), clone the repository, and confirm that conda discovers the plugin:

```console
git clone https://github.com/jezdez/conda-advise.git
cd conda-advise
pixi install --locked -e dev
pixi run --locked -e dev conda advise --help
```

Scan the environment that owns that conda executable:

```console
pixi run --locked -e dev conda advise
```

Scan another prefix and request versioned JSON output:

```console
pixi run --locked -e dev conda advise --prefix /path/to/environment --json
```

The post-solve integration only warns.
It does not add another confirmation prompt or prevent conda from continuing when a provider fails.

## Documentation

- [Getting started](https://jezdez.github.io/conda-advise/tutorials/getting-started/)
- [Installation](https://jezdez.github.io/conda-advise/how-to/install/)
- [CLI reference](https://jezdez.github.io/conda-advise/reference/cli/)
- [Provider behavior](https://jezdez.github.io/conda-advise/reference/providers/)
- [Evidence and result wording](https://jezdez.github.io/conda-advise/explanation/matching-and-evidence/)
- [Privacy](https://jezdez.github.io/conda-advise/explanation/privacy/)
- [Limitations](https://jezdez.github.io/conda-advise/explanation/limitations/)

## Development

```console
pixi run --locked -e dev check
pixi run --locked -e test test
pixi run --locked -e docs docs
pixi run --locked -e docs docs-linkcheck
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and [SECURITY.md](SECURITY.md) for private vulnerability reporting.
`conda-advise` is licensed under the BSD 3-Clause License.
