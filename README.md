# conda-advise

Security advisories usually identify an upstream project and version, while conda installs a particular artifact that can contain patches or vendored components.
Comparing names alone can produce weak matches, and a missing match can be mistaken for evidence that a package is unaffected.

`conda-advise` checks public conda-forge package records and reports the evidence behind each advisory match.
Run `conda advise` for an environment report or let the warning-only post-solve hook call attention to matches before conda changes an environment.
The common `conda advice` spelling is accepted as an alias.

The project is alpha software and has no published package release yet.
Run it from the repository's locked development environment without changing a normal conda installation.

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

The default threshold flags high and critical matches, plus every match listed in the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

![Run a conda advise scan](https://raw.githubusercontent.com/jezdez/conda-advise/main/demos/quickstart.gif)

## How matching works

```text
eligible public conda-forge package record
├── osv, default
│   └── artifact SHA-256 → Parselmouth → PyPI name and version → OSV
│       └── artifact_component evidence
└── basilisk, experimental
    └── conda-forge name and version → Prefix Basilisk
        └── upstream_version evidence
```

The default `osv` path sends the artifact's complete SHA-256 digest to Prefix's [Parselmouth](https://github.com/prefix-dev/parselmouth) service, then sends each normalized PyPI component name and exact version returned by Parselmouth to [OSV](https://osv.dev/).
Its `artifact_component` evidence means Parselmouth associated that component with the exact archive and OSV matched the component version.

For each eligible package, the opt-in `basilisk` path sends Prefix one conda package URL containing only the constant `conda` type, the constant `conda-forge` namespace, the canonical package name, and its version.
Its `upstream_version` evidence is a name-and-version match and does not establish the status of the exact conda build.

After OSV or Basilisk returns a match, its advisory identifier appears in the URL of a detail request to the same service.
When either provider returns a CVE identifier, `conda-advise` downloads the CISA catalog without sending a package, component, advisory, or CVE identifier to CISA.
Private channels, defaults, Anaconda commercial channels, local files, and unrecognized mirrors are not queried.
See [privacy](https://jezdez.github.io/conda-advise/explanation/privacy/) for request bodies, paths, normal HTTP metadata, and credentials that conda's session configuration may add.

## Interpret the result

An advisory match is a reason to inspect the exact conda build.
Neither evidence type proves that vulnerable code is shipped, reachable, enabled, or unpatched.

Coverage is reported separately from findings.
An unmapped artifact is `not_checked`, a failed attempted lookup is `incomplete`, and neither state means unaffected.
Even a completed provider query with no match is only a report about that provider's inputs and data at that time.

## Post-solve warnings

The post-solve hook checks only packages selected for linking and adds one highest-severity advisory tag to matching transaction records.
It runs for dry runs and `-y` transactions, adds no confirmation prompt, and never blocks a transaction when a provider fails.

![See a post-solve advisory warning](https://raw.githubusercontent.com/jezdez/conda-advise/main/demos/post-solve-warning.gif)

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
