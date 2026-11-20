# Project overview

## PhishGuard

PhishGuard is a defensive, educational phishing-URL classification application built with Python, Streamlit, scikit-learn, pandas, NumPy, Plotly, Matplotlib, Joblib, and SQLite. It provides account registration and login, URL feature extraction, supervised model training, per-user detection history, CSV reports, model evaluation, and role-restricted administration.

The project does not crawl URLs, contact submitted websites, download training records automatically, or claim that a model prediction guarantees a site's safety. All predictions are computed from the URL text and a model artifact trained from a supplied labeled dataset.

## Models and evaluation

The training pipeline compares a Random Forest and a Decision Tree using a stratified 80/20 holdout split. The model with the higher phishing-class F1 score is selected, with recall and accuracy as tie-breakers. The saved Joblib artifact includes the selected classifier, exact feature names, both models' evaluation metrics, confusion matrices, classification reports, dataset quality counts, and training metadata.

The model's internal convention is `1 = phishing` and `0 = legitimate`. Text labels such as `phishing`, `malicious`, `legitimate`, and `benign` are also recognized. Numeric labels can use either convention; select the phishing label during dashboard training or use `--numeric-phishing-label`. It defaults to `0`, matching UCI PhiUSIIL, whose examples and counts use `1` for legitimate and `0` for phishing. Confirm each dataset's official class legend before training.

## Data source and setup

The workspace includes the official [UCI PhiUSIIL Phishing URL dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset), downloaded from the UCI data URL and licensed CC BY 4.0. It contains 235,795 records (134,850 legitimate and 100,945 phishing). Citation: Prasad, A. & Chandra, S. (2023), “PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning,” *Computers & Security*, doi: [10.1016/j.cose.2023.103545](https://doi.org/10.1016/j.cose.2023.103545). The downloaded CSV is excluded from Git by `.gitignore` because it is a large external dataset; it remains available locally as `data/dataset.csv`. Other responsibly sourced datasets are also supported when they include actual URL strings and documented binary labels. Do not use only precomputed feature columns: this project extracts features from raw URL strings.

## Limitations

The included URL features are lexical heuristics, not domain reputation, page-content, DNS, certificate, or live threat-intelligence checks. Performance depends on dataset freshness, representativeness, label quality, and the held-out split. Treat results as risk signals and do not submit private or sensitive URLs to an installation you do not control.
