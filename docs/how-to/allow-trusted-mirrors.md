# Allow a trusted conda-forge mirror

By default, only the canonical conda-forge origin and Prefix's documented conda-forge mirror are eligible for provider lookup.
Packages from another origin remain `not_checked`.

Inspect the exact artifact URLs recorded in the target prefix before adding a mirror.
Confirm that the mirror preserves conda-forge artifacts byte for byte and that sending their identifiers to the selected provider is acceptable.

Add trusted origins as a YAML list in `.condarc`:

```yaml
plugins:
  conda_advise_conda_forge_origins:
    - https://conda.anaconda.org/conda-forge
    - https://prefix.dev/conda-forge
    - https://mirror.example.org/conda-forge
```

Use only origin paths that exclusively serve the conda-forge content you intend to identify publicly.
Do not add a private repository root merely because it also proxies conda-forge.

Only HTTPS origins are accepted.
Loopback HTTP is reserved for tests and deterministic demonstrations.

Run a manual JSON scan after editing the allowlist and inspect `coverage` reason codes before enabling post-solve warnings.
