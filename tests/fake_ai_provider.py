from app.ai.provider import AIProviderUnavailableError, GeneratedInvestigationReport
from app.ai.schemas import AnalysisEvidence, InvestigationReportContent, InvestigationRiskLevel, InvestigationStep, KeyFinding, MitreAssessment

class FakeInvestigationProvider:
    provider_name = "fake"
    model_name = "fake-investigator-v1"

    def generate_report(self,
                        evidence: AnalysisEvidence,) -> GeneratedInvestigationReport:
        report = InvestigationReportContent(
            executive_summary=(
                "Repeated authentication failures indicate a likely"
                "password-guessing attempt"
            ),
            attack_narrative=(
                "One source repeatedly attempted to authenticate aganst "
                "the same account within a short period."
            ),
            risk_level=InvestigationRiskLevel.HIGH,
            risk_score=82,
            confidence=0.94,
            key_findings=[
                KeyFinding(
                    finding=(
                        "Multiple failed authentication attempts were "
                        "detected."
                    ),
                    supporting_evidence=[
                        f"Analysis {evidence.analysis_id}",
                        "Brute-force detection alert",
                    ],
                    confidence=0.95,
                )
            ],
            mitre_assessment=[
                MitreAssessment(
                    tactic="Credential Access",
                    technique_id="T1110.001",
                    technique_name="Password Guessing",
                    explanation=(
                        "Repeated password attempts are consistent with "
                        "password guessing."
                    ),
                )
            ],
            investigation_steps=[
                InvestigationStep(
                    priority=1,
                    action="Review authentication activity for the source IP.",
                    rationale=(
                        "This will identify whether the source targeted "
                        "additional accounts."
                    ),
                    evidence_to_collect=[
                        "Authentication logs",
                        "VPN logs",
                        "Identity-provider audit logs",
                    ],
                )
            ],
            containment_recommendations=[
                "Temporarily block the source IP if activity is ongoing.",
                "Review the targeted account for successful logins.",
            ],
            evidence_gaps=[
                "No endpoint telemetry was supplied.",
            ],
            limitations=[
                "The report is based only on the stored authentication data.",
            ],
        )

        return GeneratedInvestigationReport(
            provider=self.provider_name,
            model=self.model_name,
            content=report,
        )

class UnavailableInvestigationProvider:
    provider_name = "unavailable"
    model_name = "none"

    def generate_report(self,
                        evidence: AnalysisEvidence,) -> GeneratedInvestigationReport:
        raise AIProviderUnavailableError("The test AI provider is unavailable.")

