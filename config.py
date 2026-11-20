"""Application paths and shared constants."""

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = DATA_DIR / "models"
MODEL_PATH = MODEL_DIR / "phishing_url_model.joblib"
DATASET_PATH = DATA_DIR / "dataset.csv"
DB_PATH = Path(os.environ.get("PHISHING_DB_PATH", str(DATA_DIR / "phishing_detection.db")))

APP_TITLE = "PhishGuard | URL Intelligence"
FEATURE_NAMES = (
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_subdomains",
    "has_https",
    "has_ip",
    "suspicious_keyword_count",
    "special_char_count",
    "path_length",
    "num_digits",
)