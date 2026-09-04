# Use conda-advise in CI

Run `conda advise --json` once, retain its exit status, publish the complete JSON report, show a short summary, and apply the CI policy last.
This keeps machine-readable evidence available when a qualifying finding or incomplete lookup makes the scanner return a nonzero status.
It also keeps terminal styling out of automation.

## Choose the policy

Pass an explicit provider and threshold in unattended jobs so that local conda configuration cannot change the provider selection or qualifying severity unexpectedly:

```console
conda advise --prefix /path/to/environment --provider=osv --minimum-severity high --json
```

The exit statuses are:

| Status | Meaning |
| --- | --- |
| `0` | The provider completed and no finding met the threshold |
| `1` | At least one finding met the threshold |
| `2` | The target was invalid or attempted provider work was incomplete |

Choose one of these policies:

| Policy | Status `0` | Status `1` | Status `2` |
| --- | --- | --- | --- |
| Awareness | Pass | Warn and pass | Fail |
| Gate | Pass | Fail | Fail |

The awareness policy fits an initial rollout because existing advisory matches do not immediately block development.
The gate policy is appropriate only after maintainers have reviewed existing results and decided that the configured threshold should block the job.
In both policies, status `2` fails because an incomplete attempted query must not look like a clean result.

An unmapped artifact is `not_checked` and does not by itself produce status `2`.
Your policy must still decide whether the `unmapped` and `not_checked` counts are acceptable.
Neither count means that those artifacts are safe or unaffected.

## Capture the report and status

Do not use `|| true` without first retaining the original exit status.
The report is useful for review even when the command returns `1` or `2`.

::::{tab-set}

:::{tab-item} POSIX

```sh
advise_status=0
conda advise \
  --prefix "$CONDA_PREFIX" \
  --provider=osv \
  --minimum-severity high \
  --json > conda-advise.json || advise_status=$?
printf '%s\n' "$advise_status" > conda-advise.status
```

:::

:::{tab-item} PowerShell 7

```powershell
$report = & conda advise `
  --prefix $env:CONDA_PREFIX `
  --provider=osv `
  --minimum-severity high `
  --json
$adviseStatus = $LASTEXITCODE
$report | Set-Content -LiteralPath conda-advise.json -Encoding utf8
$adviseStatus | Set-Content -LiteralPath conda-advise.status -Encoding ascii
```

:::

::::

The PowerShell example requires PowerShell 7 so that `-Encoding utf8` writes JSON without a byte-order mark.
Upload `conda-advise.json` before a final step reads `conda-advise.status` and applies the selected policy.
Keep stderr in the job log because concise provider and command diagnostics are written there rather than mixed into the JSON document.

## Validate the JSON structure

Always reject an unknown `schema_version` before consuming fields.
For structural JSON Schema validation, install the optional `jsonschema` package in the CI environment and load the schema shipped inside `conda_advise`.

::::{tab-set}

:::{tab-item} POSIX

```sh
python - <<'PY'
from importlib.resources import files
import json
from pathlib import Path

from jsonschema import Draft202012Validator

report = json.loads(Path("conda-advise.json").read_text(encoding="utf-8-sig"))
schema = json.loads(
    files("conda_advise")
    .joinpath("schema")
    .joinpath("conda-advise-report-v1.schema.json")
    .read_text(encoding="utf-8")
)
Draft202012Validator(schema).validate(report)
if report["schema_version"] != 1:
    raise SystemExit("unsupported conda-advise schema version")
PY
```

:::

:::{tab-item} PowerShell 7

```powershell
@'
from importlib.resources import files
import json
from pathlib import Path

from jsonschema import Draft202012Validator

report = json.loads(Path("conda-advise.json").read_text(encoding="utf-8-sig"))
schema = json.loads(
    files("conda_advise")
    .joinpath("schema")
    .joinpath("conda-advise-report-v1.schema.json")
    .read_text(encoding="utf-8")
)
Draft202012Validator(schema).validate(report)
if report["schema_version"] != 1:
    raise SystemExit("unsupported conda-advise schema version")
'@ | python -
```

:::

::::

This validation confirms the document structure but does not enforce optional JSON Schema formats such as `date-time`.
It does not change the coverage meaning or turn a zero-match result into a safety claim.

## Publish a GitHub Actions report

The following job fragment belongs after steps that install pinned `conda-advise` and `jsonschema` releases into the environment that owns conda and create the target prefix under the runner's temporary directory.
It defaults to the awareness policy.
Set `ADVISE_POLICY` to `gate` when qualifying findings should fail the job.

```yaml
permissions:
  contents: read

jobs:
  advise:
    runs-on: ubuntu-latest
    env:
      ADVISE_POLICY: awareness
    steps:
      # Install conda-advise and jsonschema, then create the target prefix before scanning.

      - name: Scan the environment
        id: scan
        shell: bash
        env:
          ADVISE_PREFIX: ${{ runner.temp }}/target-environment
          ADVISE_REPORT: ${{ runner.temp }}/conda-advise-report.json
        run: |
          advise_status=0
          conda advise \
            --prefix "$ADVISE_PREFIX" \
            --provider=osv \
            --minimum-severity high \
            --json > "$ADVISE_REPORT" || advise_status=$?
          printf 'status=%s\n' "$advise_status" >> "$GITHUB_OUTPUT"

      - name: Validate the JSON structure
        if: ${{ !cancelled() }}
        shell: bash
        env:
          ADVISE_REPORT: ${{ runner.temp }}/conda-advise-report.json
        run: |
          python - <<'PY'
          from importlib.resources import files
          import json
          import os
          from pathlib import Path

          from jsonschema import Draft202012Validator

          report = json.loads(Path(os.environ["ADVISE_REPORT"]).read_text(encoding="utf-8"))
          if report.get("schema_version") != 1:
              raise SystemExit("unsupported conda-advise schema version")
          schema = json.loads(
              files("conda_advise")
              .joinpath("schema")
              .joinpath("conda-advise-report-v1.schema.json")
              .read_text(encoding="utf-8")
          )
          Draft202012Validator(schema).validate(report)
          PY

      - name: Upload the JSON report
        id: upload
        if: ${{ !cancelled() }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: conda-advise-${{ github.run_id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/conda-advise-report.json
          if-no-files-found: error
          retention-days: 14

      - name: Add the job summary
        if: ${{ !cancelled() }}
        shell: bash
        env:
          ADVISE_ARTIFACT_URL: ${{ steps.upload.outputs.artifact-url }}
          ADVISE_REPORT: ${{ runner.temp }}/conda-advise-report.json
          ADVISE_STATUS: ${{ steps.scan.outputs.status }}
        run: |
          python - <<'PY'
          from __future__ import annotations

          import json
          import os
          from pathlib import Path


          def cell(value: object) -> str:
              return (
                  str(value)
                  .replace("\\", "\\\\")
                  .replace("|", "\\|")
                  .replace("\r", " ")
                  .replace("\n", " ")
              )


          report_path = Path(os.environ["ADVISE_REPORT"])
          summary_path = Path(os.environ["GITHUB_STEP_SUMMARY"])
          lines = ["## conda-advise", ""]
          try:
              report = json.loads(report_path.read_text(encoding="utf-8"))
          except (OSError, UnicodeError, json.JSONDecodeError):
              lines.append("The JSON report could not be read. Review the uploaded artifact and scanner log.")
          else:
              lines.extend(
                  [
                      "| Field | Value |",
                      "| --- | ---: |",
                      f"| Command status | {cell(os.environ['ADVISE_STATUS'])} |",
                  ]
              )
              if report.get("schema_version") != 1:
                  lines.append(f"| Schema version | Unsupported: {cell(report.get('schema_version'))} |")
              elif "summary" in report:
                  counts = report["summary"]
                  failures = report["failures"]
                  affecting_completeness = sum(
                      failure["affects_completeness"] is True for failure in failures
                  )
                  lines.extend(
                      [
                          f"| Provider | {cell(report['provider'])} |",
                          f"| Experimental provider | {cell(str(report['provider_experimental']).lower())} |",
                          f"| Minimum severity | {cell(report['minimum_severity'])} |",
                          f"| Checked | {cell(counts['checked'])} |",
                          f"| Mapped | {cell(counts['mapped'])} |",
                          f"| Unmapped | {cell(counts['unmapped'])} |",
                          f"| Not checked | {cell(counts['not_checked'])} |",
                          f"| Incomplete | {cell(counts['incomplete'])} |",
                          f"| Failures | {cell(len(failures))} |",
                          f"| Completeness-affecting failures | {cell(affecting_completeness)} |",
                          f"| Total matches | {cell(counts['total_matches'])} |",
                          f"| Qualifying matches | {cell(counts['qualifying_matches'])} |",
                      ]
                  )
              else:
                  lines.append(f"| Error | {cell(report['error']['message'])} |")
          artifact_url = os.environ.get("ADVISE_ARTIFACT_URL")
          if artifact_url:
              lines.extend(["", f"[Download the complete JSON report]({artifact_url})"])
          lines.extend(
              [
                  "",
                  "Missing, unmapped, or incomplete coverage is not evidence that an artifact is unaffected.",
                  "",
              ]
          )
          with summary_path.open("a", encoding="utf-8") as stream:
              stream.write("\n".join(lines))
          PY

      - name: Apply the advisory policy
        if: ${{ !cancelled() }}
        shell: bash
        env:
          ADVISE_STATUS: ${{ steps.scan.outputs.status }}
        run: |
          if [ "$ADVISE_POLICY" != "awareness" ] && [ "$ADVISE_POLICY" != "gate" ]; then
            echo "::error::Unknown conda-advise policy: $ADVISE_POLICY"
            exit 64
          fi
          if [ "$ADVISE_STATUS" = "0" ]; then
            exit 0
          fi
          if [ "$ADVISE_STATUS" = "1" ] && [ "$ADVISE_POLICY" = "awareness" ]; then
            echo "::warning::Review qualifying conda advisory matches in the job summary"
            exit 0
          fi
          if [ "$ADVISE_STATUS" = "1" ]; then
            echo "::error::Qualifying conda advisory matches failed the configured gate"
            exit 1
          fi
          if [ "$ADVISE_STATUS" = "2" ]; then
            echo "::error::The conda advisory scan was incomplete or its target was invalid"
            exit 2
          fi
          echo "::error::Unexpected conda-advise status: $ADVISE_STATUS"
          exit "$ADVISE_STATUS"
```

The scan step records the status and finishes successfully so later steps can publish the report.
The upload and summary steps use GitHub's recommended [`!cancelled()` status check](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions), which still runs after a previous failure but does not continue work after cancellation.
The final step is the only place that converts the recorded scanner result into the selected CI policy.

When the artifact audience is acceptable, put the complete JSON document in an artifact rather than the job log.
GitHub's [`upload-artifact` action](https://github.com/actions/upload-artifact) provides retention controls, a digest, and the `artifact-url` used by the summary.
The concise table uses [`GITHUB_STEP_SUMMARY`](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#adding-a-job-summary) so reviewers can see the provider, coverage, and match counts without expanding logs.

Review who can download workflow artifacts before uploading the full report.
It contains the exact credential-free package inventory, including names, versions, builds, filenames, hashes, and sanitized origins for private or unrecognized records that remain `not_checked`.
If that inventory is sensitive, omit the upload or send the report to storage with the required access controls while retaining a non-sensitive job summary.

## Scan pull requests and on a schedule

A pull request scan is a full snapshot of the environment that the job created.
It does not compare the pull request with the target branch and cannot claim that a finding is newly introduced.
The [OSV-Scanner pull request workflow](https://google.github.io/osv-scanner/github-action/) performs a dedicated old-versus-new comparison, but `conda-advise` v1 has no baseline comparison feature.

Run a full scan on the default branch on a schedule as well as after dependency changes.
New advisory or KEV data can qualify an unchanged environment after its last pull request ran.
A typical workflow trigger is:

```yaml
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "23 4 * * 1"
```

Use awareness mode while establishing a reviewed baseline.
Use a gate on release or deployment only when failing on every current qualifying result is the intended policy.
The [Grype CLI](https://oss.anchore.com/docs/reference/grype/cli/) similarly separates its report `--output` from its `--fail-on` threshold.
Both the [Anchore scan action](https://github.com/anchore/scan-action) and [OSV-Scanner action](https://google.github.io/osv-scanner/github-action/) separate report generation from the decision to fail a workflow.

## Keep fork scans unprivileged

Run fork pull requests with the normal `pull_request` event, a read-only token, and no secrets.
The JSON artifact and job summary do not need `security-events: write`.

GitHub normally reduces requested write permissions to read-only for fork pull requests, as described in its [`GITHUB_TOKEN` permission guidance](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#changing-the-permissions-in-a-forked-repository).
Do not switch a scanner that checks out or executes pull request content to `pull_request_target` to obtain write access.
GitHub warns that executing untrusted code with [`pull_request_target`](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target) can expose write privileges or secrets.

## Why v1 does not emit SARIF

[Grype](https://oss.anchore.com/docs/reference/grype/cli/) and OSV-Scanner can produce SARIF for GitHub code scanning, and their official actions make that format convenient for repository and dependency scans.
`conda-advise` v1 deliberately keeps its versioned JSON report instead.

GitHub requires at least one physical location for every SARIF result it displays and recommends a stable repository-relative file path for accurate annotations and fingerprints.
An installed conda `PackageRecord` identifies an artifact in a prefix, not a line in a checked-in environment file.
Assigning every finding to `environment.yml` would be inaccurate for transitive packages and would imply source locations that `conda-advise` did not discover.
See GitHub's [SARIF support requirements](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) for the location and fingerprint behavior.

SARIF can be added after `conda-advise` can map a scanned package to an exact checked-in manifest or lock-file location and can preserve stable alert identities across runs.
Until then, upload `conda-advise-report-v1` as an artifact and use the job summary for review.
Do not convert missing coverage, an unmapped artifact, an incomplete lookup, or an empty match set into a safety claim.
