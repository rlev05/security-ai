# Analyst Case Management

The Security AI platform supports persistent analyst cases for grouping security
analysis results into a longer-running investigation.

A case acts as the investigation workspace around one or more security analyses.
It allows analysts to track ownership, severity, workflow state, notes and an
append-only activity timeline.

## Case lifecycle

Cases begin in the `OPEN` state.

Supported workflow states are:

- `OPEN`
- `INVESTIGATING`
- `CONTAINED`
- `RESOLVED`
- `CLOSED`

Closing a case records a closure timestamp. Reopening a closed case clears the
previous closure timestamp.

## Severity

Cases support the following analyst-assigned severity levels:

- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`

Case severity is separate from the severity of individual detections or alerts.
This allows an analyst to represent the overall investigation risk using the
combined evidence available in the case.

## Analysis linking

Existing security analyses can be linked to cases.

A linked analysis retains its original persisted analysis record while the case
stores the relationship between the investigation and that analysis.

The API prevents the same analysis from being linked to the same case more than
once.

Normal users may only link analysis records that they are authorised to access.
Administrators retain their wider analysis visibility.

## Analyst assignment

A case can optionally be assigned to an active user.

Normal case visibility is granted when the authenticated user is either:

- the user who created the case; or
- the user currently assigned to the case.

Administrators can access all cases.

This allows an investigation to be handed to another analyst while preventing
unrelated users from browsing case information.

## Analyst notes

Visible case participants can append human-written investigation notes.

Notes are stored independently from AI-generated investigation reports so the
platform clearly separates analyst conclusions from AI-assisted output.

Each note records:

- its case;
- the author;
- the note content; and
- its creation time.

## Investigation timeline

Cases maintain an append-only timeline of important workflow activity.

Currently recorded event types include:

- case creation;
- analysis linking;
- analyst notes;
- assignment changes;
- status changes; and
- severity changes.

Timeline events record the actor and structured metadata describing the change.
For example, a status change records both the previous status and the new status.

The note timeline event stores the note identifier rather than duplicating the
note contents.

## API

Case management is exposed through authenticated FastAPI endpoints.

### Create a case

`POST /cases`

Creates a new investigation case.

### List visible cases

`GET /cases`

Returns cases created by or assigned to the authenticated user.

Administrators can list all cases.

### Get case detail

`GET /cases/{case_id}`

Returns the case together with:

- linked analyses;
- analyst notes; and
- investigation timeline events.

### Link an analysis

`POST /cases/{case_id}/analyses`

Links an authorised persisted security analysis to the case.

Duplicate links return HTTP `409 Conflict`.

### Add an analyst note

`POST /cases/{case_id}/notes`

Adds a human analyst note and records the action in the case timeline.

### Change assignment

`PATCH /cases/{case_id}/assignment`

Assigns the case to an active user or removes the current assignment.

### Change status

`PATCH /cases/{case_id}/status`

Moves the case through the investigation workflow.

### Change severity

`PATCH /cases/{case_id}/severity`

Updates the overall analyst-assigned case severity.

## Security behaviour

Case endpoints require authentication.

For normal users, inaccessible cases return HTTP `404 Not Found` rather than
revealing that another user's case exists.

Analysis linking also applies analysis ownership checks so a user cannot attach
another user's private analysis to a case they control.

Administrator access is handled through the existing application role model.

## Persistence

Case management uses four persistent database structures:

- `cases`
- `case_analysis_links`
- `case_notes`
- `case_timeline_events`

The associated Alembic migration creates these structures alongside their
foreign-key relationships to users and persisted analysis records.

Deleting a case cascades to its analysis links, notes and timeline events.

User references use `SET NULL` so historical investigation records can remain
available if a referenced user record is removed.

## Testing

The case API test suite covers:

- case creation and retrieval;
- user isolation;
- linking an owned analysis;
- duplicate link prevention;
- blocking another user's analysis;
- analyst assignment;
- assigned-user access;
- analyst notes;
- status and severity timeline tracking;
- closure timestamps; and
- administrator access.

These tests run alongside the existing authentication, detection, AI
investigation, MITRE ATT&CK grounding and threat-intelligence test suites.