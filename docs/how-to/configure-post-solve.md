# Configure post-solve warnings

The `conda_post_solves` hook checks only records that the solver plans to link.
It includes newly selected dependencies and excludes packages that remain unchanged in the prefix.

The `conda config` commands below require conda 25.5 or newer.
With conda 24.3 through 25.3, edit the active `.condarc` and use the YAML example later in this guide.

Show the current plugin settings:

```console
conda config --show plugins
```

Enable warning-only checks:

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

Change the total network budget, in seconds:

```console
conda config --set plugins.conda_advise_timeout_seconds 8
```

The allowed range is 1 through 30 seconds and the default is 5.
When the deadline expires, the hook reports incomplete coverage and lets conda continue.

For conda 24.3 through 25.3, configure the same values directly:

```yaml
plugins:
  conda_advise_post_solve: warn
  conda_advise_minimum_severity: high
  conda_advise_timeout_seconds: 5
```

The integration remains warning-only during normal installs, updates, dry runs, and commands using `-y`.
It never adds another prompt or turns a provider failure into a failed transaction.

![post-solve warning](../../demos/post-solve-warning.gif)
