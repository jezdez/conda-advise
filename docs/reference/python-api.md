# Python result API

`conda_advise.AdvisoryReport` and the result types below represent a completed scan.
Use `AdvisoryReport.to_dict()` when an application needs the versioned JSON representation.

Provider clients, component discovery, network scheduling, matching, and cache internals are not public extension points in v1.

## Report

```{eval-rst}
.. autoclass:: conda_advise.models.AdvisoryReport
   :members:
   :undoc-members:
```

## Subjects and coverage

```{eval-rst}
.. autoclass:: conda_advise.models.Subject
   :members:

.. autoclass:: conda_advise.models.Coverage
   :members:

.. autoclass:: conda_advise.models.CoverageStatus
   :members:

.. autoclass:: conda_advise.models.FailureReason
   :members:
```

## Findings and evidence

```{eval-rst}
.. autoclass:: conda_advise.models.Finding
   :members:

.. autoclass:: conda_advise.models.Evidence
   :members:

.. autoclass:: conda_advise.models.EvidenceType
   :members:

.. autoclass:: conda_advise.models.SourceRecord
   :members:

.. autoclass:: conda_advise.models.SeverityVector
   :members:

.. autoclass:: conda_advise.models.Severity
   :members:

.. autoclass:: conda_advise.models.ProviderName
   :members:
```

## Failures and summary

```{eval-rst}
.. autoclass:: conda_advise.models.ProviderFailure
   :members:

.. autoclass:: conda_advise.models.ReportSummary
   :members:
```

Use the [JSON schema](json-output.md) to exchange reports between processes.
Public model changes during the alpha period will be documented in the changelog.
