# Asynchronous investigations

AI reports are generated in the background. The API records the request and returns quickly; a Celery worker does the slow provider work afterwards.

This avoids tying up an HTTP request while waiting on Redis, an AI provider or threat-intelligence enrichment.

## Request path

When an authenticated user requests an investigation report, the API first checks that the user can access the stored analysis. It then creates an investigation-report row in PostgreSQL with a `pending` status and sends only that report ID to the Celery queue.

If the queue accepts the task, the endpoint returns `202 Accepted`.

If Redis is unavailable and the task cannot be queued, the report is marked as failed and the API returns `503 Service Unavailable`. This prevents a report from being left in a misleading pending state when no worker can ever receive it.

## Worker path

The Celery worker receives the report ID, reloads the report and associated analysis from PostgreSQL, builds the investigation evidence, gathers ATT&CK context and optional threat-intelligence data, then calls the configured AI provider.

A successful result is validated and persisted before the report status moves to `completed`. Provider errors, validation failures and other processing errors move the report to `failed` with an error message recorded in PostgreSQL.

The normal lifecycle is therefore:

```text
pending -> completed
        \
         -> failed
```

PostgreSQL is the source of truth for report state. Celery result storage is not used as the application's report database.

## Why Redis messages are small

The queue payload contains the investigation report identifier rather than the full analysis.

That keeps raw logs, user information, API keys and large analysis payloads out of Redis. The worker loads the authoritative data directly from PostgreSQL when it starts the task.

It also means the task sees the stored analysis in the same form used by the rest of the application rather than relying on a second copy embedded in a queue message.

## Duplicate delivery

Workers only process reports that are still pending. If the same task is delivered again after a report has already completed or failed, the worker does not generate a second report for the same record.

This is a small but useful protection against the at-least-once delivery behaviour common to background queues.

## Reading report status

The latest investigation report for an analysis is available through:

```text
GET /analysis/history/{analysis_id}/ai-report
```

The dashboard uses the same stored state when it displays investigation progress and results.

## Runtime components

FastAPI owns authentication, authorisation and report creation. PostgreSQL stores analyses and report state. Redis is the Celery broker. The worker performs enrichment and generation. The local ATT&CK repository supplies trusted technique context, while external AI and threat-intelligence providers are optional integrations.

If AI is disabled, the rest of the analysis platform continues to work normally; only report generation is unavailable.
