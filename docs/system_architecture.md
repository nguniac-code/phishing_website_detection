# System architecture

```text
Browser
  └── Streamlit UI (app.py)
       ├── Authentication service (auth.py)
       │    └── PBKDF2-HMAC-SHA256 password hashes
       ├── Detection service (prediction.py)
       │    ├── Shared URL normalization/features (feature_extraction.py)
       │    └── Trained Joblib artifact (data/models/)
       ├── Training and evaluation (train_model.py)
       │    ├── Labeled CSV validation
       │    ├── Stratified train/test split
       │    └── Random Forest vs Decision Tree
       └── SQLite persistence (database.py)
            ├── Users, password hashes, roles, and enabled/disabled status
            └── User-owned detections
```

## Request flow

1. A visitor registers or signs in. Registration always assigns the `user` role. Passwords are salted and hashed using PBKDF2-HMAC-SHA256; plaintext passwords are never persisted.
2. The app reloads the account from SQLite on each Streamlit rerun and derives the available navigation from its database role.
3. A signed-in user submits a URL. The app validates and normalizes it without fetching the URL, derives the same ordered features used for training, loads the saved model, predicts, and stores the result for that account.
4. Users can inspect only their own history and download a CSV report of that history.
5. An administrator can train both classifiers from an uploaded CSV, review registered accounts and recent platform-wide URL activity, change other accounts' roles, and enable or disable their access. Disabled accounts are rejected at sign-in and logged out on their next request. The last enabled administrator is protected from being disabled. The dataset upload is processed in memory; the trained artifact is written locally.

## Model lifecycle

`train_model.py` rejects missing columns, invalid URLs, unknown labels, duplicate URLs, and datasets without both classes. After a stratified holdout evaluation, it selects by phishing F1, then recall and accuracy, and atomically replaces the artifact. Prediction validates the artifact's feature schema before inference. Only trusted locally generated Joblib files should be loaded; Joblib artifacts use Python serialization and must not be accepted from untrusted sources.

## Access control

Public registration cannot assign administrator privileges. Create the initial administrator from a trusted local shell with `python auth.py create-admin`. Admin navigation and operations are guarded by the role reloaded from the database, and the last administrator cannot be demoted or disabled. SQLite queries use bound parameters and detection records reference their owning user with a foreign key.
