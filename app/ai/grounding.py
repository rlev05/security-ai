from app.ai.provider import (
    AIProviderResponseError,
)
from app.ai.schemas import (
    EvidenceBasis,
    InvestigationReportContent,
    MitreAssessment,
)
from app.knowledge.schemas import (
    AttackGroundingContext,
)


def validate_and_normalise_grounded_report(
    report: InvestigationReportContent,
    context: AttackGroundingContext,
) -> InvestigationReportContent:
    """Validate AI ATT&CK claims against trusted retrieved data."""

    allowed = {
        technique.technique_id: technique
        for technique in context.techniques
    }

    normalised_mitre: list[
        MitreAssessment
    ] = []

    for assessment in report.mitre_assessment:
        technique_id = (
            assessment.technique_id
            .strip()
            .upper()
        )

        technique = allowed.get(
            technique_id
        )

        if technique is None:
            raise AIProviderResponseError(
                "AI report referenced an ATT&CK technique "
                "that was not present in the retrieved "
                f"knowledge context: {technique_id}"
            )

        normalised_mitre.append(
            assessment.model_copy(
                update={
                    "technique_id": (
                        technique.technique_id
                    ),
                    "technique_name": (
                        technique.name
                    ),
                    "tactic": ", ".join(
                        technique.tactics
                    ),
                }
            )
        )

    normalised_evidence = []

    for evidence in report.evidence_assessment:
        technique_ids = [
            technique_id.strip().upper()
            for technique_id
            in evidence.technique_ids
        ]

        for technique_id in technique_ids:
            if technique_id not in allowed:
                raise AIProviderResponseError(
                    "AI evidence assessment referenced "
                    "an ATT&CK technique outside the "
                    f"retrieved context: {technique_id}"
                )

        if (
            evidence.basis
            == EvidenceBasis.ATTACK_KNOWLEDGE
            and not technique_ids
        ):
            raise AIProviderResponseError(
                "ATT&CK knowledge claims must reference "
                "at least one retrieved technique."
            )

        normalised_evidence.append(
            evidence.model_copy(
                update={
                    "technique_ids": technique_ids,
                }
            )
        )

    return report.model_copy(
        update={
            "mitre_assessment": (
                normalised_mitre
            ),
            "evidence_assessment": (
                normalised_evidence
            ),
        }
    )

