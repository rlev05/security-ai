from app.knowledge.attack_repository import extract_detected_technique_ids
from tests.fake_attack_knowledge import build_fake_attack_repository


def test_extracts_detected_attack_ids() -> None:
    result = {
        "incidents": [
            {
                "alerts": [
                    {
                        "mitre_technique_id": (
                            "T1110.001"
                        )
                    },
                    {
                        "mitre_technique_id": (
                            "T1078"
                        )
                    },
                ]
            }
        ]
    }

    technique_ids = (
        extract_detected_technique_ids(
            result
        )
    )

    assert technique_ids == [
        "T1078",
        "T1110.001",
    ]


def test_retrieves_known_technique() -> None:
    repository = (
        build_fake_attack_repository()
    )

    technique = repository.get_technique(
        "T1110.001"
    )

    assert technique is not None
    assert technique.name == "Password Guessing"


def test_builds_grounding_from_detection() -> None:
    repository = (
        build_fake_attack_repository()
    )

    context = (
        repository.build_grounding_context(
            {
                "incidents": [
                    {
                        "alerts": [
                            {
                                "mitre_technique_id": (
                                    "T1110.003"
                                )
                            }
                        ]
                    }
                ]
            }
        )
    )

    assert len(context.techniques) == 1

    assert (
        context.techniques[0].technique_id
        == "T1110.003"
    )


def test_tracks_unknown_techniques() -> None:
    repository = (
        build_fake_attack_repository()
    )

    context = (
        repository.build_grounding_context(
            {
                "alerts": [
                    {
                        "mitre_technique_id": (
                            "T9999.999"
                        )
                    }
                ]
            }
        )
    )

    assert context.techniques == []

    assert context.unresolved_technique_ids == [
        "T9999.999"
    ]

