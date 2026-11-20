"""URL prediction using the persisted, dataset-trained model artifact."""

from pathlib import Path

import pandas as pd

from config import FEATURE_NAMES, MODEL_PATH
from feature_extraction import extract_url_features, normalize_url
from train_model import load_model_artifact


def predict_url(url: str, model_path: str | Path = MODEL_PATH) -> dict:
    normalized_url = normalize_url(url)
    artifact = load_model_artifact(model_path)
    features = pd.DataFrame(
        [extract_url_features(normalized_url)],
        columns=FEATURE_NAMES,
    )
    model = artifact["model"]
    prediction = int(model.predict(features)[0])
    confidence = None
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)[0]
        class_indexes = list(model.classes_)
        confidence = float(probabilities[class_indexes.index(prediction)])
    return {
        "url": normalized_url,
        "result": "phishing" if prediction == 1 else "legitimate",
        "confidence": confidence,
        "model_name": artifact["model_name"],
    }