import json
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


ATTACK_VERSION = "19.1"

PROJECT_ROOT = Path(__file__).resolve().parents[1]

OUTPUT_DIRECTORY = (
    PROJECT_ROOT
    / "app"
    / "knowledge"
    / "data"
)

OUTPUT_PATH = (
    OUTPUT_DIRECTORY
    / "enterprise_attack_v19_1.json"
)

LICENSE_PATH = (
    OUTPUT_DIRECTORY
    / "ATTACK_LICENSE.txt"
)

BASE_URL = (
    "https://raw.githubusercontent.com/"
    "mitre-attack/attack-stix-data/"
    f"v{ATTACK_VERSION}"
)

ATTACK_DATA_URL = (
    f"{BASE_URL}/enterprise-attack/"
    "enterprise-attack.json"
)

ATTACK_LICENSE_URL = (
    f"{BASE_URL}/LICENSE.txt"
)

COPYRIGHT_NOTICE = (
    "© 2026 The MITRE Corporation. "
    "This work is reproduced and distributed with the "
    "permission of The MITRE Corporation."
)


def download_bytes(
    url: str,
) -> bytes:
    request = Request(
        url,
        headers={
            "User-Agent": (
                "security-ai ATT&CK knowledge updater"
            )
        },
    )

    with urlopen(
        request,
        timeout=120,
    ) as response:
        return response.read()


def is_active_object(
    obj: dict[str, Any],
) -> bool:
    return not (
        obj.get("revoked", False)
        or obj.get("x_mitre_deprecated", False)
    )


def get_attack_reference(
    obj: dict[str, Any],
) -> dict[str, Any] | None:
    for reference in obj.get(
        "external_references",
        [],
    ):
        if (
            reference.get("source_name")
            == "mitre-attack"
        ):
            return reference

    return None


def get_external_id(
    obj: dict[str, Any],
) -> str | None:
    reference = get_attack_reference(obj)

    if reference is None:
        return None

    external_id = reference.get("external_id")

    if isinstance(external_id, str):
        return external_id

    return None


def get_source_url(
    obj: dict[str, Any],
) -> str | None:
    reference = get_attack_reference(obj)

    if reference is None:
        return None

    url = reference.get("url")

    if isinstance(url, str):
        return url

    return None


def build_snapshot(
    payload: dict[str, Any],
) -> dict[str, Any]:
    objects = payload.get("objects")

    if not isinstance(objects, list):
        raise ValueError(
            "ATT&CK STIX bundle does not contain an objects list"
        )

    active_objects = [
        obj
        for obj in objects
        if (
            isinstance(obj, dict)
            and is_active_object(obj)
        )
    ]

    objects_by_id = {
        obj["id"]: obj
        for obj in active_objects
        if isinstance(obj.get("id"), str)
    }

    tactic_names = {
        obj["x_mitre_shortname"]: obj["name"]
        for obj in active_objects
        if (
            obj.get("type") == "x-mitre-tactic"
            and isinstance(
                obj.get("x_mitre_shortname"),
                str,
            )
            and isinstance(obj.get("name"), str)
        )
    }

    relationships: dict[
        tuple[str, str],
        list[str],
    ] = defaultdict(list)

    for obj in active_objects:
        if obj.get("type") != "relationship":
            continue

        relationship_type = obj.get(
            "relationship_type"
        )

        target_ref = obj.get("target_ref")
        source_ref = obj.get("source_ref")

        if not all(
            isinstance(value, str)
            for value in (
                relationship_type,
                target_ref,
                source_ref,
            )
        ):
            continue

        relationships[
            (
                relationship_type,
                target_ref,
            )
        ].append(source_ref)

    techniques: list[dict[str, Any]] = []

    for technique in active_objects:
        if technique.get("type") != "attack-pattern":
            continue

        technique_id = get_external_id(technique)

        if (
            technique_id is None
            or not technique_id.startswith("T")
        ):
            continue

        source_url = get_source_url(technique)

        if source_url is None:
            continue

        tactic_values: set[str] = set()

        for phase in technique.get(
            "kill_chain_phases",
            [],
        ):
            if not isinstance(phase, dict):
                continue

            if (
                phase.get("kill_chain_name")
                != "mitre-attack"
            ):
                continue

            short_name = phase.get("phase_name")

            if not isinstance(short_name, str):
                continue

            tactic_values.add(
                tactic_names.get(
                    short_name,
                    short_name.replace(
                        "-",
                        " ",
                    ).title(),
                )
            )

        mitigations: list[
            dict[str, Any]
        ] = []

        for source_ref in relationships.get(
            (
                "mitigates",
                technique["id"],
            ),
            [],
        ):
            mitigation = objects_by_id.get(
                source_ref
            )

            if (
                mitigation is None
                or mitigation.get("type")
                != "course-of-action"
            ):
                continue

            mitigation_id = get_external_id(
                mitigation
            )

            if mitigation_id is None:
                continue

            mitigations.append(
                {
                    "mitigation_id": mitigation_id,
                    "name": mitigation.get(
                        "name",
                        mitigation_id,
                    ),
                    "description": mitigation.get(
                        "description"
                    ),
                    "source_url": get_source_url(
                        mitigation
                    ),
                }
            )

        detection_strategies: list[
            dict[str, Any]
        ] = []

        for source_ref in relationships.get(
            (
                "detects",
                technique["id"],
            ),
            [],
        ):
            strategy = objects_by_id.get(
                source_ref
            )

            if (
                strategy is None
                or strategy.get("type")
                != "x-mitre-detection-strategy"
            ):
                continue

            strategy_id = get_external_id(
                strategy
            )

            if strategy_id is None:
                continue

            analytics: list[
                dict[str, Any]
            ] = []

            for analytic_ref in strategy.get(
                "x_mitre_analytic_refs",
                [],
            ):
                if not isinstance(
                    analytic_ref,
                    str,
                ):
                    continue

                analytic = objects_by_id.get(
                    analytic_ref
                )

                if analytic is None:
                    continue

                analytic_id = get_external_id(
                    analytic
                )

                if analytic_id is None:
                    analytic_id = analytic_ref

                analytics.append(
                    {
                        "analytic_id": analytic_id,
                        "name": analytic.get(
                            "name",
                            analytic_id,
                        ),
                        "description": analytic.get(
                            "description"
                        ),
                    }
                )

            analytics.sort(
                key=lambda item: item[
                    "analytic_id"
                ]
            )

            detection_strategies.append(
                {
                    "strategy_id": strategy_id,
                    "name": strategy.get(
                        "name",
                        strategy_id,
                    ),
                    "description": strategy.get(
                        "description"
                    ),
                    "source_url": get_source_url(
                        strategy
                    ),
                    "analytics": analytics,
                }
            )

        mitigations.sort(
            key=lambda item: item[
                "mitigation_id"
            ]
        )

        detection_strategies.sort(
            key=lambda item: item[
                "strategy_id"
            ]
        )

        techniques.append(
            {
                "technique_id": technique_id,
                "name": technique.get(
                    "name",
                    technique_id,
                ),
                "description": technique.get(
                    "description",
                    "",
                ),
                "tactics": sorted(
                    tactic_values
                ),
                "platforms": sorted(
                    technique.get(
                        "x_mitre_platforms",
                        [],
                    )
                ),
                "source_url": source_url,
                "mitigations": mitigations,
                "detection_strategies": (
                    detection_strategies
                ),
            }
        )

    techniques.sort(
        key=lambda item: item["technique_id"]
    )

    return {
        "metadata": {
            "attack_version": ATTACK_VERSION,
            "domain": "enterprise-attack",
            "source_url": ATTACK_DATA_URL,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "copyright_notice": (
                COPYRIGHT_NOTICE
            ),
        },
        "techniques": techniques,
    }


def main() -> None:
    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    print(
        f"Downloading MITRE ATT&CK v{ATTACK_VERSION}..."
    )

    attack_data = download_bytes(
        ATTACK_DATA_URL
    )

    payload = json.loads(
        attack_data.decode("utf-8")
    )

    snapshot = build_snapshot(payload)

    OUTPUT_PATH.write_text(
        json.dumps(
            snapshot,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "Downloading ATT&CK license..."
    )

    license_data = download_bytes(
        ATTACK_LICENSE_URL
    )

    LICENSE_PATH.write_bytes(
        license_data
    )

    print(
        f"Wrote {len(snapshot['techniques'])} "
        "Enterprise ATT&CK techniques to "
        f"{OUTPUT_PATH}"
    )

    print(
        f"License copied to {LICENSE_PATH}"
    )


if __name__ == "__main__":
    main()