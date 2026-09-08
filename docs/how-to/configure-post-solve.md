# Configure post-solve warnings

Post-solve warnings are enabled by default.
The `conda_post_solves` hook checks packages the solver plans to link, including newly selected dependencies.
Packages that remain unchanged are not checked by the hook.

The `conda config` commands below require conda 25.5 or newer.
With conda 24.3 through 25.3, edit the active `.condarc` and use the YAML example later in this guide.

Show the current plugin settings:

```console
conda config --show plugins
```

Restore the default warning mode:

```console
conda config --set plugins.conda_advise_post_solve warn
```

Disable automatic checks while keeping `conda advise` available:

```console
conda config --set plugins.conda_advise_post_solve off
```

Set the minimum displayed warning severity:

```console
conda config --set plugins.conda_advise_minimum_severity high
```

Valid values are `low`, `medium`, `high`, and `critical`.
A CISA KEV match always qualifies for a warning even when its calculated severity is below the configured threshold.

Change the advisory scan deadline, in seconds:

```console
conda config --set plugins.conda_advise_timeout_seconds 8
```

The allowed range is 1 through 30 seconds and the default is 5.
The deadline starts when package-record scanning begins and includes subject normalization, cache access, provider requests, and optional KEV enrichment.
When it expires, the hook reports incomplete coverage and lets conda continue.
Unfinished HTTP request workers are terminated at the deadline.

For conda 24.3 through 25.3, configure the same values directly:

```yaml
plugins:
  conda_advise_post_solve: warn
  conda_advise_minimum_severity: high
  conda_advise_timeout_seconds: 5
```

The hook runs before conda creates the transaction, including during dry runs and `-y` commands.
It adds no prompt and catches ordinary scan exceptions so provider failures let conda continue.

![post-solve warning](../../demos/post-solve-warning.gif)
