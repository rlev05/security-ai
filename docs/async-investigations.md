# Asynchronous AI Investigations

AI investigation reports are processed outside the HTTP request lifecycle.

## Request flow

An authenticated analyst requests an investigation report.

The API:

1. verifies access to the stored analysis
2. creates a pending investigation report in PostgreSQL
3. sends only the report ID to the Redis task queue
4. returns HTTP 202 Accepted

The API does not wait for the language model.

## Worker flow

A Celery worker receives the report ID and:

1. loads the pending report from PostgreSQL
2. loads the associated security analysis
3. retrieves trusted MITRE ATT&CK grounding
4. calls the configured AI provider
5. validates generated ATT&CK references
6. stores the grounded report
7. updates the report status to completed

Provider or validation failures are stored as failed reports.

## Components

FastAPI
→ receives requests and handles authentication

PostgreSQL
→ source of truth for users, analyses and report status

Redis
→ task-message broker

Celery
→ background task processing

MITRE ATT&CK repository
→ trusted cybersecurity grounding

AI provider
→ structured investigation generation

## Report lifecycle

Reports move through the following states:

    pending
       |
       +----> completed
       |
       +----> failed

PostgreSQL is the authoritative source for these states.

Celery result storage is not used.

## Idempotency

A worker only processes reports with a pending status.

Reports that are already completed or failed are not processed again.

This prevents duplicate task delivery from generating duplicate investigation
results.

## Failure handling

If Redis cannot accept a task, the API records the report as failed and returns
HTTP 503.

If background processing fails after the task has been accepted, the worker
records the failure in PostgreSQL.

The client can retrieve the latest state through:

    GET /analysis/history/{analysis_id}/ai-report

## Security

Task messages contain only the investigation report identifier.

Raw logs, user credentials, API keys and complete analysis results are not sent
through Redis.

The worker retrieves authoritative investigation data directly from PostgreSQL.