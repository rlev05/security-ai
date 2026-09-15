# Threat-intelligence enrichment

Threat intelligence is optional supporting context for an investigation. It is not part of the core detection decision and it is not treated as proof that an observed event is malicious.

The application extracts indicators from stored analysis data, normalises and deduplicates them, then sends only eligible indicators to the configured provider.

## Indicator extraction

The IOC layer currently recognises:

- IPv4 addresses
- domains
- MD5 hashes
- SHA-1 hashes
- SHA-256 hashes

Extraction is provider-independent. A provider only receives an indicator after the local extraction and eligibility checks have already run.

## AbuseIPDB

v1.0 includes an AbuseIPDB provider for public IPv4 enrichment.

Private, loopback, link-local, reserved and other non-global addresses are filtered out locally and are not submitted. Complete logs are never sent to AbuseIPDB; the provider receives the individual IP address being checked.

The provider can be disabled completely through configuration, which is the default development posture unless an API key and provider setting are supplied.

## Cache behaviour

Successful enrichment results are stored in PostgreSQL. The default cache lifetime is 24 hours, so repeated investigations involving the same provider and indicator can reuse a recent result without another external request.

Failed lookups are also recorded for visibility, but a failed result is not considered a valid positive cache entry.

This matters because "the provider could not answer" and "the provider returned no concerning reputation" are not the same thing.

## Failure handling

Threat-intelligence enrichment is deliberately non-blocking for AI investigations.

If the provider is unavailable, the failed enrichment is added to the investigation context and report generation can continue. The report instructions make it clear that a failed or skipped enrichment must not be interpreted as a clean reputation result.

## Data flow

The relevant part of the pipeline is:

```text
stored analysis
    -> IOC extraction
    -> normalisation / deduplication
    -> eligibility checks
    -> PostgreSQL cache
    -> optional external lookup
    -> investigation evidence
```

ATT&CK retrieval and AI generation happen later. Threat intelligence is kept as its own evidence category so a reputation score cannot silently become a deterministic detection conclusion.

## Privacy and queueing

Redis task messages contain only the investigation report ID. The worker loads the analysis from PostgreSQL, extracts indicators locally and submits eligible values to the configured provider.

Raw logs and complete analysis payloads are not placed on the Celery queue and are not sent to the threat-intelligence provider.

For an internet-facing deployment, the usual external-service considerations still apply: protect the provider API key, review the provider's data-handling terms, and only enable enrichment if sending eligible indicators outside the application is acceptable for the environment.
