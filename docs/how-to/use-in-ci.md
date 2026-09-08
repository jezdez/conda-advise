# Use conda-advise in CI

Save the JSON report and exit status before applying your CI policy.
This preserves the report for review when findings or incomplete lookups produce a nonzero status.

## Choose the policy

Pass an explicit provider and severity threshold so local configuration cannot change them:

```console
conda advise --prefix /path/to/environment --provider=osv --minimum-severity high --json
```

| Status | Meaning |
| --- | --- |
| `0` | No incomplete lookup or qualifying finding. Some subjects may remain `not_checked` |
| `1` | At least one qualifying finding and no incomplete lookup |
| `2` | Command failure or incomplete provider or CISA KEV work. Takes precedence over findings |

Two possible policies are:

| Policy | Status `0` | Status `1` | Status `2` |
| --- | --- | --- | --- |
| Awareness | Pass | Warn and pass | Fail |
| Gate | Pass | Fail | Fail |

Awareness mode lets maintainers review existing matches before making them block a job.
Both examples fail on status `2`.
Unmapped artifacts are `not_checked` and do not themselves cause status `2`, so decide separately which coverage gaps are acceptable.

## Capture the report and status

Retain the original exit status when redirecting JSON output:

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
Keep stderr in the job log for provider and command diagnostics.

## Publish a GitHub Actions report

Run this fragment from the [source checkout](install.md) after `pixi install --locked -e dev` and creation of the target prefix.
The development environment includes `jsonschema`.
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
      # Check out conda-advise, install its Pixi environment, and create the target prefix.

      - name: Scan the environment
        id: scan
        shell: bash
        env:
          ADVISE_PREFIX: ${{ runner.temp }}/target-environment
          ADVISE_REPORT: ${{ runner.temp }}/conda-advise-report.json
        run: |
          advise_status=0
          pixi run --locked -e dev conda advise \
            --prefix "$ADVISE_PREFIX" \
            --provider=osv \
            --minimum-severity high \
            --json > "$ADVISE_REPORT" || advise_status=$?
          printf 'status=%s\n' "$advise_status" >> "$GITHUB_OUTPUT"

      - name: Validate and summarize the report
        id: validate
        if: ${{ !cancelled() }}
        shell: bash
        env:
          ADVISE_REPORT: ${{ runner.temp }}/conda-advise-report.json
        run: |
          pixi run --locked -e dev python - <<'PYTHON'
          import json
          import os
          from pathlib import Path

          from jsonschema import Draft202012Validator, ValidationError

          try:
              report = json.loads(Path(os.environ["ADVISE_REPORT"]).read_text(encoding="utf-8"))
          except (OSError, UnicodeError, json.JSONDecodeError):
              raise SystemExit("The advisory report could not be read")
          if not isinstance(report, dict) or report.get("schema_version") != 1:
              raise SystemExit("Unsupported conda-advise schema version")
          schema = json.loads(
              Path("schema/conda-advise-report-v1.schema.json")
              .read_text(encoding="utf-8")
          )
          try:
              Draft202012Validator(schema).validate(report)
          except ValidationError:
              raise SystemExit("The advisory report did not pass schema validation")
          if "summary" not in report:
              raise SystemExit("The scanner returned an error document")

          lines = ["## conda-advise", "", "| Field | Count |", "| --- | ---: |"]
          for field in (
              "checked", "mapped", "unmapped", "not_checked", "incomplete",
              "total_matches", "qualifying_matches",
          ):
              lines.append(f"| {field.replace('_', ' ')} | {report['summary'][field]} |")
          lines.extend(["", "Missing coverage is not evidence that an artifact is unaffected.", ""])
          with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
              stream.write("\n".join(lines))
          PYTHON

      - name: Upload the JSON report
        if: ${{ !cancelled() }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: conda-advise-${{ github.run_id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/conda-advise-report.json
          if-no-files-found: error
          retention-days: 14

      - name: Apply the advisory policy
        if: ${{ !cancelled() }}
        shell: bash
        env:
          ADVISE_STATUS: ${{ steps.scan.outputs.status }}
          ADVISE_VALIDATION: ${{ steps.validate.outcome }}
        run: |
          if [ "$ADVISE_VALIDATION" != "success" ]; then
            echo "::error::The advisory report could not be validated"
            exit 2
          fi
          case "$ADVISE_POLICY:$ADVISE_STATUS" in
            awareness:0|gate:0) exit 0 ;;
            awareness:1)
              echo "::warning::Review qualifying advisory matches in the report"
              exit 0 ;;
            gate:1)
              echo "::error::Qualifying advisory matches failed the configured gate"
              exit 1 ;;
            awareness:2|gate:2)
              echo "::error::The advisory scan failed or was incomplete"
              exit 2 ;;
            *)
              echo "::error::Unexpected advisory policy or scanner status"
              exit 2 ;;
          esac
```

The scan step captures its status so later steps can publish the report.
The validation step checks the [versioned JSON schema](../reference/json-output.md) before writing counts to [`GITHUB_STEP_SUMMARY`](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#adding-a-job-summary).
It does not enforce optional JSON Schema formats such as `date-time`.
The [`!cancelled()` condition](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions) lets the report upload run after a failure.
The final step applies the chosen policy.

Review the artifact audience before uploading a full report.
It includes the credential-free package inventory, including private or unrecognized records that remain `not_checked`.
For sensitive inventories, keep only a non-sensitive summary in GitHub and store the report with appropriate access controls.

Advisory summaries, aliases, fixes, URLs, errors, and `source_records[].data` are provider-controlled input.
Escape them for the destination before using them in logs, Markdown, HTML, or shell code.
The example summary uses only fixed labels and validated counts.

## Scan pull requests and on a schedule

Each scan reports the environment as it exists at that moment.
It does not identify findings introduced by a pull request.
[OSV-Scanner's pull request workflow](https://google.github.io/osv-scanner/github-action/) provides that comparison for its supported inputs.

Schedule scans as well as running them after dependency changes.
New advisories or KEV entries can affect an unchanged environment:

```yaml
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "23 4 * * 1"
```

The [Grype CLI](https://oss.anchore.com/docs/reference/grype/cli/) and [Anchore scan action](https://github.com/anchore/scan-action) also provide report output and configurable failure thresholds.
See [related tools](../explanation/ecosystem-comparison.md) for their supported inputs.

## Keep fork scans unprivileged

Use the normal `pull_request` event, a read-only token, and no secrets for fork scans.
JSON artifacts and job summaries do not need `security-events: write`.
See GitHub's [fork permission guidance](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#changing-the-permissions-in-a-forked-repository).

Do not run untrusted pull request code under [`pull_request_target`](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target), which can expose write privileges and secrets.

## JSON and SARIF

V1 provides JSON output, with no SARIF export.
GitHub's [SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) requires physical source locations for displayed findings.
An installed conda package record does not identify a line in a checked-in manifest or lockfile.
Assigning every match to `environment.yml` would misidentify transitive packages and other records without a known source location.
Use the JSON artifact and job summary for review.
