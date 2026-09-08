# conda-advise

`conda-advise` adds security advisory reports and package warnings to [conda](https://docs.conda.io/).
Run `conda advise` to check an environment, or receive a warning when a conda transaction includes an advisory match.

The project is in alpha and has no published release yet.
To try it, follow the [source installation guide](https://jezdez.github.io/conda-advise/how-to/install/) and [getting-started tutorial](https://jezdez.github.io/conda-advise/tutorials/getting-started/).

![Run a conda advise scan](https://raw.githubusercontent.com/jezdez/conda-advise/main/demos/quickstart.gif)

## Documentation

The [documentation](https://jezdez.github.io/conda-advise/) covers setup, usage, and how to interpret results:

- [Command-line reference](https://jezdez.github.io/conda-advise/reference/cli/) and [JSON output](https://jezdez.github.io/conda-advise/reference/json-output/)
- [Configure transaction warnings](https://jezdez.github.io/conda-advise/how-to/configure-post-solve/)
- [Run offline](https://jezdez.github.io/conda-advise/how-to/use-offline/) or [use in CI](https://jezdez.github.io/conda-advise/how-to/use-in-ci/)
- [Matching and evidence](https://jezdez.github.io/conda-advise/explanation/matching-and-evidence/), [privacy](https://jezdez.github.io/conda-advise/explanation/privacy/), and [coverage limits](https://jezdez.github.io/conda-advise/explanation/limitations/)

## Related projects

`conda-advise` uses [OSV](https://osv.dev/), Prefix's [Parselmouth](https://github.com/prefix-dev/parselmouth) mappings, and its experimental [Basilisk](https://basilisk.prefix.dev/status) provider.
For package inventories and attestations, see [conda-sboms](https://github.com/conda-incubator/conda-sboms) and [conda-sigstore](https://github.com/jezdez/conda-sigstore).
The [related-tools guide](https://jezdez.github.io/conda-advise/explanation/ecosystem-comparison/) also covers [OSV-Scanner](https://google.github.io/osv-scanner/), [Grype](https://oss.anchore.com/docs/guides/vulnerability/), and Anaconda's environment security services.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidance, and [SECURITY.md](SECURITY.md) to report a vulnerability privately.
Licensed under the [BSD 3-Clause License](LICENSE).
