"""Dataset validation, model training, evaluation, and artifact persistence."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import BinaryIO

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

from config import FEATURE_NAMES, MODEL_DIR, MODEL_PATH
from feature_extraction import extract_features, normalize_url


_URL_COLUMNS = ("url", "link", "website", "uri", "domain")
_LABEL_COLUMNS = ("label", "status", "class", "result", "type", "is_phishing", "phishing")
_PHISHING_LABELS = {"phishing", "phish", "malicious", "fraudulent", "bad"}
_LEGITIMATE_LABELS = {"legitimate", "legit", "benign", "good", "safe"}


def _read_csv(source: str | Path | bytes | bytearray | BinaryIO) -> pd.DataFrame:
    if isinstance(source, (bytes, bytearray)):
        return pd.read_csv(BytesIO(source))
    return pd.read_csv(source)


def _find_column(frame: pd.DataFrame, aliases: tuple[str, ...]) -> str | None:
    columns = {str(column).strip().lower(): str(column) for column in frame.columns}
    for alias in aliases:
        if alias in columns:
            return columns[alias]
    return None


def _map_label(value: object, numeric_phishing_label: int) -> int | None:
    if pd.isna(value):
        return None
    if isinstance(value, (int, float, np.integer, np.floating)):
        numeric = float(value)
        return int(numeric == numeric_phishing_label) if numeric in (0.0, 1.0) else None
    text = str(value).strip().lower()
    if text in {"0", "0.0", "1", "1.0"}:
        numeric = int(float(text))
        return int(numeric == numeric_phishing_label)
    if text in _PHISHING_LABELS:
        return 1
    if text in _LEGITIMATE_LABELS:
        return 0
    return None


def prepare_dataset(
    source: str | Path | bytes | bytearray | BinaryIO,
    numeric_phishing_label: int = 0,
) -> tuple[pd.DataFrame, pd.Series, dict[str, int]]:
    """Load URL and label columns, normalize records, and remove invalid/duplicate rows."""
    if numeric_phishing_label not in (0, 1):
        raise ValueError("Numeric phishing label must be either 0 or 1.")
    try:
        frame = _read_csv(source)
    except (pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise ValueError(f"Could not read the CSV dataset: {exc}") from exc
    if frame.empty:
        raise ValueError("The CSV dataset contains no records.")

    url_column = _find_column(frame, _URL_COLUMNS)
    label_column = _find_column(frame, _LABEL_COLUMNS)
    if url_column is None or label_column is None:
        raise ValueError(
            "CSV must contain a URL column (for example 'url') and a label column "
            "(for example 'label')."
        )

    total = len(frame)
    rows: list[tuple[str, int]] = []
    invalid_urls = 0
    invalid_labels = 0
    missing_records = 0
    for raw_url, raw_label in zip(frame[url_column], frame[label_column]):
        if pd.isna(raw_url) or pd.isna(raw_label):
            missing_records += 1
            continue
        label = _map_label(raw_label, numeric_phishing_label)
        if label is None:
            invalid_labels += 1
            continue
        try:
            url = normalize_url(str(raw_url))
        except ValueError:
            invalid_urls += 1
            continue
        rows.append((url, label))

    cleaned = pd.DataFrame(rows, columns=("url", "label"))
    before_deduplication = len(cleaned)
    cleaned = cleaned.drop_duplicates(subset="url", keep="first").reset_index(drop=True)
    duplicates = before_deduplication - len(cleaned)
    if cleaned.empty:
        raise ValueError("No valid, labeled URLs remain after dataset validation.")
    if set(cleaned["label"].unique()) != {0, 1}:
        raise ValueError("Dataset must include both classes: 0 = legitimate and 1 = phishing.")
    features = extract_features(cleaned["url"].tolist())
    labels = cleaned["label"].astype("int8")
    summary = {
        "rows_in_file": total,
        "valid_rows": len(cleaned),
        "duplicates_removed": duplicates,
        "invalid_urls": invalid_urls,
        "invalid_labels": invalid_labels,
        "missing_records": missing_records,
        "legitimate": int((labels == 0).sum()),
        "phishing": int((labels == 1).sum()),
        "numeric_phishing_label": numeric_phishing_label,
    }
    return features, labels, summary


def _evaluate(model: object, x_test: pd.DataFrame, y_test: pd.Series) -> dict:
    predictions = model.predict(x_test)
    return {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, pos_label=1, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, pos_label=1, zero_division=0)),
        "f1_score": float(f1_score(y_test, predictions, pos_label=1, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, predictions, labels=[0, 1]).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            zero_division=0,
            output_dict=True,
        ),
    }


def train_models(
    source: str | Path | bytes | bytearray | BinaryIO,
    model_path: str | Path = MODEL_PATH,
    numeric_phishing_label: int = 0,
) -> dict:
    """Train and compare both classifiers; choose the model by phishing F1 then recall."""
    features, labels, dataset_summary = prepare_dataset(
        source, numeric_phishing_label=numeric_phishing_label
    )
    if labels.value_counts().min() < 3:
        raise ValueError("At least three unique URLs from each class are required for a stratified split.")
    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )
    candidates = {
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ),
        "Decision Tree": DecisionTreeClassifier(
            class_weight="balanced",
            min_samples_leaf=2,
            random_state=42,
        ),
    }
    evaluations: dict[str, dict] = {}
    for name, model in candidates.items():
        model.fit(x_train, y_train)
        evaluations[name] = _evaluate(model, x_test, y_test)

    selected_name = max(
        evaluations,
        key=lambda name: (
            evaluations[name]["f1_score"],
            evaluations[name]["recall"],
            evaluations[name]["accuracy"],
            name == "Random Forest",
        ),
    )
    destination = Path(model_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": candidates[selected_name],
        "model_name": selected_name,
        "feature_names": list(FEATURE_NAMES),
        "metrics": evaluations,
        "selected_metrics": evaluations[selected_name],
        "dataset_summary": dataset_summary,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "test_size": len(y_test),
        "train_size": len(y_train),
        "selection_metric": "phishing-class F1-score, with recall and accuracy as tie-breakers",
    }
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=".phishing-model-",
            suffix=".joblib",
            dir=destination.parent,
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
        joblib.dump(artifact, temporary_path)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.unlink(temporary_path)
    return artifact


def load_model_artifact(model_path: str | Path = MODEL_PATH) -> dict:
    path = Path(model_path)
    if not path.is_file():
        raise FileNotFoundError(
            f"No trained model found at {path}. Train it with train_model.py or the administrator dashboard."
        )
    artifact = joblib.load(path)
    if (
        not isinstance(artifact, dict)
        or "model" not in artifact
        or artifact.get("feature_names") != list(FEATURE_NAMES)
    ):
        raise ValueError("The saved model artifact is invalid or uses an incompatible feature schema.")
    return artifact


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Train PhishGuard using a labeled URL CSV.")
    parser.add_argument(
        "dataset",
        nargs="?",
        default=str(Path(__file__).resolve().parent / "data" / "dataset.csv"),
        help="CSV file with URL and label columns (default: data/dataset.csv)",
    )
    parser.add_argument("--model-path", default=str(MODEL_PATH))
    parser.add_argument(
        "--numeric-phishing-label",
        type=int,
        choices=(0, 1),
        default=0,
        help="Which numeric CSV label means phishing (default: 0, as in UCI PhiUSIIL).",
    )
    arguments = parser.parse_args()
    try:
        trained = train_models(
            arguments.dataset,
            arguments.model_path,
            numeric_phishing_label=arguments.numeric_phishing_label,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Selected model: {trained['model_name']}")
    print(f"Training records: {trained['train_size']}; test records: {trained['test_size']}")
    for name, metrics in trained["metrics"].items():
        print(
            f"{name}: accuracy={metrics['accuracy']:.3f}, "
            f"precision={metrics['precision']:.3f}, recall={metrics['recall']:.3f}, "
            f"F1={metrics['f1_score']:.3f}"
        )