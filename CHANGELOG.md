# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial warning-only `conda advise` plugin implementation.
- `conda advice` alias for the common noun spelling.
- Rich terminal reports with accessible text labels and structured advisory, coverage, and failure output.
- Locked noarch package builds and GitHub environment-gated publication to the `jezdez` Anaconda.org channel.

### Changed

- Made interactive post-solve advisory warnings visually distinct from conda transaction output while preserving plain stderr output for logs.
- Corrected documentation about provider eligibility, coverage, exit statuses, post-solve timing, cache behavior, and untrusted provider data.
- Shortened the documentation and added links to related advisory, inventory, and verification projects.
- Added `CONDA_ADVISE_CACHE_PATH` to select a cache file on every supported platform.

### Fixed

- Bound provider response sizes, component and advisory counts, pagination, and cache storage. Requests that exceed their deadline are terminated.
- Reject provider proxy authentication challenges before conda can forward proxy credentials.
- Reject malformed and excessively encoded package URLs without exposing embedded credentials.
- Classify each CVSS vector using its own version before choosing the highest severity.
- Isolate demonstration servers, temporary files, and caches from other local processes and the user's advisory data.
- Require successful runs of the designated main workflows before publishing a release.

[Unreleased]: https://github.com/jezdez/conda-advise/commits/main
