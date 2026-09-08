# Related tools and services

`conda-advise` uses existing mapping and advisory services.
Other conda tools provide package inventories, attestations, file scans, and environment policy.

## Mapping and advisory data

[Parselmouth](https://github.com/prefix-dev/parselmouth) maps conda artifacts to PyPI components.
The default provider looks up an artifact SHA-256 there, then queries [OSV](https://osv.dev/) with the returned component names and versions.
OSV collects advisory data from [multiple sources](https://google.github.io/osv.dev/data/), including the [PyPA advisory database](https://github.com/pypa/advisory-database).

Prefix's [Basilisk](https://basilisk.prefix.dev/status) provides a conda-forge vulnerability explorer and API.
The experimental `basilisk` provider queries it with conda names and versions, including packages that may lack a Parselmouth mapping.
See [provider behavior](../reference/providers.md) for the evidence returned by each path.

## Inventories and attestations

[conda-sboms](https://github.com/conda-incubator/conda-sboms) generates software bills of materials from conda environments.
Use it to record package inventories in SBOM formats.

[conda-sigstore](https://github.com/jezdez/conda-sigstore) creates and verifies Sigstore attestations for conda packages.
Attestations can provide signed evidence about an artifact.
`conda-advise` does not currently consume SBOM or VEX attestations.

## Other scanners

[OSV-Scanner](https://google.github.io/osv-scanner/) checks project dependencies against OSV, with support for lockfiles, SBOMs, directories, and containers.
Its [GitHub workflow](https://google.github.io/osv-scanner/github-action/) can compare changes introduced by a pull request.

[Grype](https://oss.anchore.com/docs/guides/vulnerability/) scans container images, filesystems, and SBOMs for known vulnerabilities.
Prefix's [supply-chain guide](https://prefix.dev/blog/securing-the-supply-chain) includes an example using Grype on a conda environment.
These tools inspect different inputs from `conda-advise`, so their coverage and matches can differ.

## Anaconda environment security

Anaconda's [environment monitoring](https://www.anaconda.com/docs/anaconda-platform/admin/environments), [policies](https://www.anaconda.com/docs/anaconda-platform/admin/policies), and [CVE management](https://www.anaconda.com/docs/anaconda-platform/admin/cve) support authenticated scans and organizational package policy.
Its [SBOM documentation](https://www.anaconda.com/blog/sboms-at-anaconda) describes the component data used for package assessment.

`conda-advise` does not query these services.
With the default allowed origins, ordinary Anaconda commercial and private-channel records remain `not_checked`.
See [privacy](privacy.md) for how artifact URLs determine eligibility.
