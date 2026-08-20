from typing import Any
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from app.anomaly.features import FEATURE_NAMES, build_event_features
from app.anomaly.schemas import AnomalyDetectionResult, EventAnomaly


DEFAULT_CONTAMINATION = 0.05
MINIMUM_EVENTS = 20
RANDOM_STATE = 42

def _build_reason_list(
        features: dict[str, float],
) -> list[str]:
    reasons: list[str] = []

    if features["is_login_failure"] >= 1.0:
        reasons.append("Authentication failure contributed to the anomaly score.")

    if features["ip_failure_count"] >= 5.0:
        reasons.append("Source IP generated a high number of authentication failures.")

    if features["user_failure_count"] >= 5.0:
        reasons.append("Account received a high number of authentication failures.")

    if features["distinct_users_for_ip"] >= 5.0:
        reasons.append("Source IP interacted with an unusually broad set of accounts.")

    if 0.0 < features["seconds_since_previous_ip_event"] <= 5.0:
        reasons.append("Source IP produced events in a short time interval.")

    if not reasons:
        reasons.append(
            "Combined behavioural features differed from the surrounding event population."
        )

    return reasons


def _normalise_anomaly_scores(
        raw_scores: list[float],
) -> list[float]:
    if not raw_scores:
        return []

    minimum = min(raw_scores)

    maximum = max(raw_scores)

    if maximum == minimum:
        return [0.0 for _ in raw_scores]

    return [(score - minimum) / (maximum - minimum) for score in raw_scores]


def detect_event_anomalies(
        events: list[dict[str, Any]],
        *,
        contamination: float = DEFAULT_CONTAMINATION,
) -> AnomalyDetectionResult:
    """
    Detect behavioural anomalies in security events using Isolation Forest.

    This detector is intentionally independent from deterministic security
    rules. Rules identify known attack patterns, while this model highlights
    events that differ statistically from the supplied event population.
    """

    if not (0.0 < contamination < 0.5):
        raise ValueError("contamination must be greater than 0 and less than 0.5")

    if len(events) < MINIMUM_EVENTS:
        return AnomalyDetectionResult(
            model_name=("IsolationForest"),
            model_version=(sklearn.__version__),
            total_events=len(events),
            analysed_events=0,
            anomaly_count=0,
            contamination=(contamination),
            feature_names=list(FEATURE_NAMES),
            anomalies=[],
            skipped_reason=(
                f"At least {MINIMUM_EVENTS} events are required for anomaly detection."
            ),
        )

    feature_rows = build_event_features(events)

    matrix = [[row[name] for name in FEATURE_NAMES] for row in feature_rows]

    scaler = RobustScaler()

    scaled_matrix = scaler.fit_transform(matrix)

    model = IsolationForest(
        n_estimators=200,
        contamination=(contamination),
        random_state=(RANDOM_STATE),
        n_jobs=1,
    )

    predictions = model.fit_predict(scaled_matrix)

    # IsolationForest score_samples() gives lower values
    # to more abnormal samples. Negating turns larger
    # values into more anomalous values.
    raw_anomaly_scores = [float(-score) for score in model.score_samples(scaled_matrix)]

    normalised_scores = _normalise_anomaly_scores(raw_anomaly_scores)

    anomalies: list[EventAnomaly] = []

    for index, prediction in enumerate(predictions):
        if prediction != -1:
            continue

        features = feature_rows[index]

        anomalies.append(
            EventAnomaly(
                event_index=index,
                anomaly_score=round(
                    normalised_scores[index],
                    6,
                ),
                reasons=(_build_reason_list(features)),
                features={
                    name: round(
                        features[name],
                        6,
                    )
                    for name in FEATURE_NAMES
                },
                event=events[index],
            )
        )

    anomalies.sort(
        key=lambda anomaly: anomaly.anomaly_score,
        reverse=True,
    )

    return AnomalyDetectionResult(
        model_name=("IsolationForest"),
        model_version=(sklearn.__version__),
        total_events=len(events),
        analysed_events=len(events),
        anomaly_count=len(anomalies),
        contamination=(contamination),
        feature_names=list(FEATURE_NAMES),
        anomalies=anomalies,
        skipped_reason=None,
    )

