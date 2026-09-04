# Related tools and services

`conda-advise` is an open client for public conda-forge advisory awareness.
It does not duplicate existing dashboards, file scanners, or commercial policy products.

## Prefix Parselmouth and Basilisk

[Parselmouth](https://github.com/prefix-dev/parselmouth) provides the exact artifact-to-PyPI-component association used by the default provider.
Its artifact hash gives `conda-advise` more specific evidence than a name-only mapping.

[Basilisk](https://basilisk.prefix.dev/status) is Prefix's hosted conda-forge vulnerability-matching dashboard and API.
It combines upstream identity mappings and vulnerability sources across more packages than the PyPI-component path can cover.
`conda-advise` exposes it as an experimental opt-in provider rather than creating another dashboard.

Prefix also demonstrates [Grype against materialized conda environments](https://prefix.dev/blog/securing-the-supply-chain).
Grype scans files and package metadata present in a prefix.
It is a complementary independent scan and is not invoked or required by `conda-advise`.

## Anaconda security products

Anaconda documents authenticated environment scans, artifact-status curation, activation checks, environment logging, dashboards, and policy enforcement in its [environment security tools](https://www.anaconda.com/docs/anaconda-platform/admin/environments), [policies](https://www.anaconda.com/docs/anaconda-platform/admin/policies), and [CVE management](https://www.anaconda.com/docs/anaconda-platform/admin/cve).
Anaconda also describes its [package SBOMs and their use for component matching](https://www.anaconda.com/blog/sboms-at-anaconda).

Those paid services can associate curated states such as active, cleared, mitigated, and disputed with artifacts and organizational policy.
`conda-advise` does not query paid APIs, store Anaconda credentials, inspect private channels, or replace `anaconda audit scan`.

Any future Anaconda integration should live in Anaconda-owned code, use `anaconda-auth`, and preserve product entitlements.

## Future artifact evidence

`conda-sboms` can describe exact conda package identities.
`conda-sigstore` can verify signed package-bound evidence.
A future conda-forge workflow could combine package-specific SBOM or VEX attestations with those projects.

V1 does not infer such evidence from current package metadata and does not create a separate advisory database.
