import json
from pathlib import Path
from typing import Any

from app.knowledge.schemas import (
    AttackGroundingContext,
    AttackKnowledgeSnapshot,
    AttackTechniqueKnowledge,
)


DEFAULT_ATTACK_KNOWLEDGE_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "enterprise_attack_v19_1.json"
)


class AttackKnowledgeUnavailableError(
    RuntimeError
):
    """Raised when the local ATT&CK knowledge base cannot be loaded."""


class AttackKnowledgeRepository:
    """Local indexed repository of trusted ATT&CK knowledge."""

    def __init__(
        self,
        snapshot: AttackKnowledgeSnapshot,
    ) -> None:
        self.snapshot = snapshot

        self._techniques = {
            technique.technique_id.upper(): technique
            for technique in snapshot.techniques
        }

    @classmethod
    def from_file(
        cls,
        path: Path = DEFAULT_ATTACK_KNOWLEDGE_PATH,
    ) -> "AttackKnowledgeRepository":
        if not path.exists():
            raise AttackKnowledgeUnavailableError(
                "MITRE ATT&CK knowledge data is missing. "
                "Run scripts/update_attack_knowledge.py."
            )

        try:
            payload = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )

            snapshot = (
                AttackKnowledgeSnapshot.model_validate(
                    payload
                )
            )
        except (
            OSError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            raise AttackKnowledgeUnavailableError(
                "MITRE ATT&CK knowledge data could not be loaded."
            ) from exc

        return cls(snapshot)

    def get_technique(
        self,
        technique_id: str,
    ) -> AttackTechniqueKnowledge | None:
        return self._techniques.get(
            technique_id.strip().upper()
        )

    def get_techniques(
        self,
        technique_ids: list[str],
    ) -> list[AttackTechniqueKnowledge]:
        result: list[
            AttackTechniqueKnowledge
        ] = []

        seen: set[str] = set()

        for technique_id in technique_ids:
            normalised = (
                technique_id
                .strip()
                .upper()
            )

            if normalised in seen:
                continue

            seen.add(normalised)

            technique = self.get_technique(
                normalised
            )

            if technique is not None:
                result.append(technique)

        return result

    def build_grounding_context(
        self,
        result_json: dict[str, Any],
    ) -> AttackGroundingContext:
        detected_ids = (
            extract_detected_technique_ids(
                result_json
            )
        )

        matched = self.get_techniques(
            detected_ids
        )

        matched_ids = {
            technique.technique_id
            for technique in matched
        }

        unresolved = [
            technique_id
            for technique_id in detected_ids
            if technique_id not in matched_ids
        ]

        return AttackGroundingContext(
            attack_version=(
                self.snapshot.metadata.attack_version
            ),
            techniques=matched,
            unresolved_technique_ids=unresolved,
        )


def extract_detected_technique_ids(
    value: Any,
) -> list[str]:
    """Find ATT&CK IDs emitted by the detection engine.

    This deliberately retrieves only IDs already present in the
    deterministic analysis result rather than allowing the LLM to
    choose arbitrary ATT&CK techniques.
    """

    technique_ids: set[str] = set()

    def visit(
        current: Any,
    ) -> None:
        if isinstance(current, dict):
            for key, child in current.items():
                if (
                    key == "mitre_technique_id"
                    and isinstance(child, str)
                    and child.strip()
                ):
                    technique_ids.add(
                        child.strip().upper()
                    )
                else:
                    visit(child)

        elif isinstance(current, list):
            for child in current:
                visit(child)

    visit(value)

    return sorted(technique_ids)