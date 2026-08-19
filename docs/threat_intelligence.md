# Threat Intelligence Enrichment

The Security AI Platform extracts indicators of compromise from stored security
analysis data before generating an AI investigation report.

## Supported indicators

The extraction layer currently recognizes:

- IPv4 addresses
- domains
- MD5 hashes
- SHA-1 hashes
- SHA-256 hashes

The extraction layer is provider-independent.

## External enrichment

The initial external provider is AbuseIPDB.

Only public IP addresses are eligible for AbuseIPDB enrichment.

Private, loopback, link-local, reserved and otherwise non-global IP addresses
are not sent to external providers.

Complete logs are never sent to the threat-intelligence service.

## Investigation pipeline

Stored analysis

→ IOC extraction

→ indicator normalization and deduplication

→ public-IP validation

→ PostgreSQL enrichment cache

→ optional AbuseIPDB lookup

→ MITRE ATT&CK retrieval

→ structured AI investigation

→ grounding validation

→ persistence

## Caching

Successful enrichment results are cached in PostgreSQL.

The default cache lifetime is 24 hours.

Repeated investigations involving the same provider and indicator can therefore
reuse a recent reputation result without performing another external request.

Failed lookups are persisted for visibility but are not treated as valid cache
entries.

## Failure handling

Threat-intelligence enrichment is supporting context rather than a hard
dependency.

If a provider is unavailable:

- the indicator is marked as failed
- the failure is included in the investigation context
- AI report generation continues

A failed enrichment is never interpreted as evidence that an indicator is safe.

## Evidence separation

AI investigations distinguish:

- observed evidence
- deterministic detection conclusions
- MITRE ATT&CK knowledge
- threat-intelligence enrichment
- AI inference

Threat-intelligence reputation is supporting context and does not by itself
prove that an IP address was responsible for malicious activity.

## Privacy

Task messages sent through Redis continue to contain only the investigation
report identifier.

The Celery worker retrieves analysis data from PostgreSQL, extracts individual
indicators locally and only submits eligible indicators to the configured
provider.