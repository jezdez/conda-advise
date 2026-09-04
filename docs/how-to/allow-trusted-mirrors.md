# Allow a trusted conda-forge mirror

By default, only records whose sanitized artifact URLs match the canonical conda-forge or Prefix mirror URL prefixes are eligible for provider lookup.
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

Use only origin paths that exclusively serve the conda-forge content you intend to identify publicly.
Do not add a private repository root merely because it also proxies conda-forge.
Adding an origin authorizes every recognized record below that URL path for provider lookup, including private records if the configured path contains them.
The implementation does not verify the channel field, filename, or digest against conda-forge metadata, so configure a URL path only when all matching records are safe to identify to the provider.

Validation accepts HTTPS origins and plain HTTP only for `localhost`, `127.0.0.1`, and `::1`.
Loopback HTTP is unencrypted and should be used only for local tests and deterministic demonstrations.

Run a manual JSON scan after editing the allowlist and inspect `coverage` reason codes before enabling post-solve warnings.
