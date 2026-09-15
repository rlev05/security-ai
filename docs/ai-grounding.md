# AI grounding

The AI investigation feature sits at the end of the analysis pipeline, not at the beginning. Security AI does not ask a model to look at a raw log and decide what happened. Parsing and deterministic detections run first, and the report is generated from the evidence that already exists in the application.

That distinction is important because it gives the report a fixed evidence boundary.

## Where ATT&CK mappings come from

ATT&CK technique IDs originate in the deterministic detection layer. When a rule identifies behaviour such as password spraying or brute-force activity, the application records the technique IDs associated with that rule.

Before an AI report is generated, those IDs are looked up in the project's local Enterprise ATT&CK snapshot. Only the retrieved technique records are supplied to the provider. The model is not asked to discover extra ATT&CK mappings on its own.

After generation, the report is checked again. A report that references an ATT&CK technique outside the supplied grounding context is rejected rather than silently accepted.

The pipeline is roughly:

```text
authentication log
    -> parser
    -> structured security events
    -> deterministic detections
    -> incidents / alerts
    -> ATT&CK technique IDs
    -> local ATT&CK lookup
    -> investigation evidence
    -> AI provider
    -> structured report validation
    -> persistence
```

## Keeping evidence types separate

The investigation schema distinguishes between several kinds of information instead of flattening everything into one narrative:

- observations taken from the stored analysis
- conclusions produced by deterministic detections
- ATT&CK knowledge retrieved by the application
- threat-intelligence context, when enabled
- AI-generated interpretation

This makes it harder for generated text to be mistaken for an original log observation. It also makes missing evidence easier to call out explicitly.

## Local ATT&CK data

The repository contains a local Enterprise ATT&CK snapshot generated from MITRE's STIX 2.1 data. v1.0 pins version 19.1 so that investigations and tests are reproducible instead of changing whenever upstream ATT&CK content changes.

To refresh the snapshot:

```powershell
python scripts/update_attack_knowledge.py
```

The ATT&CK licence file is stored next to the generated data and should remain there when the snapshot is updated.

## Prompt-injection and output controls

Log content is treated as evidence, not as instructions. Usernames, hostnames, IP addresses, raw messages and other values are placed inside the investigation context as untrusted data.

The provider instructions explicitly tell the model not to follow instructions found inside logs and not to invent events, infrastructure, identities, malware, vulnerabilities, attacker motives or additional ATT&CK techniques.

The returned report is parsed into a structured Pydantic model. Invalid structured output fails the investigation instead of being stored as a successful report.

The application also stores the grounding context used for the report. That gives an analyst a record of the material the model was allowed to use when the report was produced.

## What grounding does not guarantee

Grounding reduces the amount of freedom the model has, but it does not turn generated text into fact. The report is still an analyst aid and should be read alongside the original analysis, detections and case notes.

A high-confidence report should still be traceable back to supplied evidence. When the available evidence is weak or incomplete, the report schema has explicit places for evidence gaps and limitations rather than encouraging the model to fill them in.
