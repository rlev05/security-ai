from datetime import datetime, timezone
from app.knowledge.attack_repository import AttackKnowledgeRepository
from app.knowledge.schemas import AttackDetectionStrategyKnowledge, AttackKnowledgeMetadata, AttackKnowledgeSnapshot, AttackMitigationKnowledge, AttackTechniqueKnowledge

def build_fake_attack_repository() -> (
    AttackKnowledgeRepository
):
    techniques = [
        AttackTechniqueKnowledge(
            technique_id="T1110.001",
            name="Password Guessing",
            description=(
                "Repeated password attempts against "
                "an account may indicate password guessing."
            ),
            tactics=[
                "Credential Access",
            ],
            platforms=[
                "Linux",
                "Windows",
            ],
            source_url=(
                "https://attack.mitre.org/"
                "techniques/T1110/001"
            ),
            mitigations=[
                AttackMitigationKnowledge(
                    mitigation_id="M1032",
                    name=(
                        "Multi-factor Authentication"
                    ),
                    description=(
                        "Additional authentication factors "
                        "can reduce credential abuse risk."
                    ),
                    source_url=None,
                )

            ],
            detection_strategies=[
                AttackDetectionStrategyKnowledge(
                    strategy_id="DET0551",
                    name=(
                        "Password Guessing Detection"
                    ),
                    description=(
                        "Correlate repeated authentication "
                        "failures."
                    ),
                    source_url=None,
                )
            ]
        ),
        AttackTechniqueKnowledge(
            technique_id="T1110.003",
            name="Password Spraying",
            description=(
                "Authentication attempts across multiple "
                "accounts may indicate password spraying."
            ),
            tactics=[
                "Credential Access",
            ],
            platforms=[
                "Linux",
                "Windows",
            ],
            source_url=(
                "https://attack.mitre.org/"
                "techniques/T1110/003/"
            ),
        ),
        AttackTechniqueKnowledge(
            technique_id="T1078",
            name="Valid Accounts",
            description=(
                "Existing accounts can be abused after"
                "credentials have been compromised."
            ),
            tactics=[
                "Defense Evasion",
                "Initial Access",
                "Persistence",
                "Privilege Escalation"
            ],
            platforms=[
                "Linux",
                "Windows",
            ],
            source_url=(
                "https://attack.mitre.org/"
                "techniques/T1078"
            ),
        ),
    ]

    snapshot = AttackKnowledgeSnapshot(
        metadata=AttackKnowledgeMetadata(
            attack_version="test",
            domain="enterprise-attack",
            source_url="https://example.com/test",
            generated_at=datetime.now(timezone.utc),
            copyright_notice="Test data",
        ),
        techniques=techniques,
    )

    return AttackKnowledgeRepository(snapshot)


