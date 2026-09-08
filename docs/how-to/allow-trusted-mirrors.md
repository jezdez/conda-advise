# Allow a trusted conda-forge mirror

By default, only records with artifact URLs beneath the canonical conda-forge channel or Prefix mirror are eligible for provider lookup.
Records with another URL remain `not_checked`.

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

Use a path containing only conda-forge packages you intend to identify publicly.
Adding an origin permits lookup of every recognized record beneath it, including private records.
The client does not verify the channel field, filename, or digest against conda-forge metadata.
See [privacy](../explanation/privacy.md) before adding a repository that also hosts private packages.

Validation accepts HTTPS origins and plain HTTP only for `localhost`, `127.0.0.1`, and `::1`.
Loopback HTTP is unencrypted and should be used only for local tests and deterministic demonstrations.

Run a manual JSON scan after editing the allowlist and inspect its `coverage` reason codes.
The new origins also apply to the default post-solve warnings.
