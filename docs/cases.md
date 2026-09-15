# Analyst cases

Cases are the part of Security AI used for work that lasts longer than a single analysis. An analyst can group related analyses, keep notes, assign responsibility and track how an investigation changes over time.

The original analysis records remain intact. A case stores links to them rather than copying or replacing the underlying results.

## Case state

A new case starts as `OPEN`. The supported states are:

```text
OPEN
INVESTIGATING
CONTAINED
RESOLVED
CLOSED
```

Closing a case records a closure time. Reopening it clears that timestamp so the current state is not contradicted by an old close date.

Case severity is assigned separately from individual alert severity. The available values are `LOW`, `MEDIUM`, `HIGH` and `CRITICAL`. That gives the analyst room to judge the whole investigation instead of inheriting the highest severity from one detection automatically.

## Visibility and assignment

A normal user can see a case when they created it or when the case is currently assigned to them. Administrators can access all cases.

Assignments can be changed to another active user or cleared. This supports a simple hand-off workflow without making every case visible to every account.

For normal users, inaccessible cases return `404 Not Found`. The API does not use a different response that would reveal that a hidden case exists.

## Linking analyses

An existing stored analysis can be linked to a case as long as the user is allowed to access that analysis. The same analysis cannot be linked to the same case twice; duplicate links return `409 Conflict`.

Ownership checks are applied at link time, so having access to a case does not let a user attach somebody else's private analysis to it.

## Notes and timeline

Analyst notes are stored separately from AI-generated reports. This is intentional: a human conclusion should remain distinguishable from generated investigation text.

Each note records its author, case, content and creation time.

Cases also have an append-only activity timeline. It records important changes such as case creation, analysis links, notes, assignment changes, status changes and severity changes. Timeline entries store the actor and structured metadata about the change. For example, a status event records both the previous and new values.

A note timeline event references the note ID rather than duplicating the note body.

## API endpoints

The authenticated case API includes:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/cases` | Create a case |
| `GET` | `/cases` | List cases visible to the current user |
| `GET` | `/cases/{case_id}` | Return case detail, linked analyses, notes and timeline |
| `POST` | `/cases/{case_id}/analyses` | Link an existing analysis |
| `POST` | `/cases/{case_id}/notes` | Add an analyst note |
| `PATCH` | `/cases/{case_id}/assignment` | Change or clear assignment |
| `PATCH` | `/cases/{case_id}/status` | Change workflow status |
| `PATCH` | `/cases/{case_id}/severity` | Change overall case severity |

The dashboard exposes the same case workflow for browser users.

## Persistence

Case data is split across four database structures:

- `cases`
- `case_analysis_links`
- `case_notes`
- `case_timeline_events`

Deleting a case removes its links, notes and timeline entries. User references use `SET NULL` where appropriate so historical investigation records can survive the deletion of a user account.

The schema is created through Alembic alongside the rest of the application database.

## Test coverage

The case tests cover creation, retrieval, user isolation, administrator visibility, analysis ownership, duplicate links, assignment, assigned-user access, notes, timeline changes and closure timestamps.
