# PhishGuard — Phishing Website Detection System

A final-year B.Tech Computer Science project: a Streamlit application for phishing-URL classification using a real, user-supplied labeled dataset, Random Forest and Decision Tree comparison, secure account authentication, per-user detection history, CSV reports, and an administrator dashboard.

> **The training data is not fabricated.** The workspace includes the official UCI PhiUSIIL dataset (CC BY 4.0); the CSV is excluded from Git because it is a 56 MB external dataset.

## Features

- PBKDF2-HMAC-SHA256 password hashing, registration, login, logout, and user/admin roles.
- Admin account directory with role management, enable/disable controls, disabled-account login/session enforcement, and protected last-admin access.
- Admin platform activity dashboard with aggregate detection metrics and filterable recent URL checks.
- SQLite persistence with user-scoped detection history and CSV downloads.
- Lexical URL features: length, domain length, dots, hyphens, subdomains, HTTPS, IP usage, suspicious keywords, special characters, path length, and digits.
- Stratified train/test evaluation of Random Forest and Decision Tree; model selection prioritizes phishing-class F1.
- Joblib persistence and a shared feature-extraction function for training and inference.
- Evaluation dashboard with accuracy, precision, recall, F1, confusion matrix, classification report, and a Plotly comparison chart.
- Admin upload-and-train workflow and account role management.

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python download_dataset.py
python auth.py create-admin
streamlit run app.py
```

Alternatively, create the first administrator after starting the application; the sign-in page documents the command. From a separate terminal, train directly:

```powershell
python train_model.py data\dataset.csv
```

The CSV needs a raw URL column (`url`, `link`, `website`, `uri`, or `domain`) and a label column (`label`, `status`, `class`, `result`, `type`, `is_phishing`, or `phishing`). Text labels such as `phishing` and `legitimate` are supported. UCI PhiUSIIL uses `0 = phishing`, `1 = legitimate`; use `--numeric-phishing-label 1` for sources where `1 = phishing`. Always check the source's label documentation. At least three unique valid URLs for each class are required.

## Dataset

The [UCI PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) is retrieved from the official [UCI CSV URL](https://archive.ics.uci.edu/static/public/967/data.csv) by `python download_dataset.py` if it is not already present. It includes 235,795 records and is licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Citation: Prasad, A. & Chandra, S. (2023), *Computers & Security*, doi: [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545). The CSV is excluded from Git to avoid committing a large external dataset. Dataset uploads in the dashboard are processed in memory and are not saved there.

## Project layout

```text
app.py                    Streamlit UI and role-restricted navigation
auth.py                   Registration, password hashing, admin bootstrap
config.py                 Shared paths and feature schema
database.py               SQLite schema and persistence
feature_extraction.py     URL validation, normalization, deterministic features
prediction.py             Inference using the trained artifact
train_model.py            CSV validation, model training and evaluation
assets/style.css          Application theme
data/dataset.csv          Empty location for your labeled dataset
data/models/              Locally generated model artifacts
docs/                     Project and system documentation
tests/                    Core unit tests
```

## Run tests

```powershell
python -m unittest discover -s tests -v
```

## Safety and limitations

The application classifies URL text only; it never visits the submitted website. Its lexical features do not include live reputation, DNS, TLS, or page-content analysis. A prediction is not a safety guarantee. Treat Joblib model files as trusted local artifacts—loading an untrusted serialized model can execute code.
