# Grounded AI Investigation Pipeline

The Security AI Platform combines deterministic security detections with
retrieved MITRE ATT&CK knowledge before requesting an AI investigation report.

## Trust model

The language model does not decide which ATT&CK techniques initially apply.

Technique IDs originate from deterministic detection rules. The platform then
retrieves matching records from a locally stored MITRE ATT&CK snapshot.

Only this retrieved knowledge is supplied to the AI provider.

Generated ATT&CK references are validated again after generation. A report that
references a technique outside the retrieved context is rejected.

## Investigation pipeline

Authentication log

→ parsing

→ security events

→ deterministic detection rules

→ incidents and alerts

→ ATT&CK technique IDs

→ local MITRE ATT&CK retrieval

→ grounded AI context

→ structured AI investigation report

→ grounding validation

→ persistence

## Evidence separation

AI reports label statements as one of:

- observed evidence
- detection-engine conclusion
- ATT&CK knowledge
- AI inference

This prevents model-generated interpretation from being presented as if it were
raw security evidence.

## ATT&CK data

The local Enterprise ATT&CK snapshot is generated from the official MITRE ATT&CK
STIX 2.1 dataset.

The project currently pins ATT&CK version 19.1 for reproducibility.

Refresh the local snapshot with:

    python scripts/update_attack_knowledge.py

The generated ATT&CK license file is stored alongside the local dataset.

## AI safety controls

The investigation layer:

- treats log content as untrusted input
- does not follow instructions contained inside logs
- validates structured AI output
- restricts ATT&CK references to retrieved techniques
- records missing evidence and limitations
- stores the grounding context used for each investigation
- records failed generation attempts