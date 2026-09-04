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

[Unreleased]: https://github.com/jezdez/conda-advise/commits/main
