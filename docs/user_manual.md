# User manual

## Installation

1. Install Python 3.10 or later.
2. In the project folder, create and activate a virtual environment.
3. Install dependencies with `pip install -r requirements.txt`.
4. Start the interface with `streamlit run app.py`.

The SQLite database is initialized automatically. Since the repository intentionally contains no invented training data, URL analysis remains unavailable until an administrator trains a model.

## Create the first administrator

From a trusted terminal in the project folder, run `python auth.py create-admin`. The password is requested without echo and must be at least 10 characters. Then sign in to Streamlit using that account. Public self-registration cannot create an administrator.

## Obtain and prepare a dataset

Run `python download_dataset.py` to obtain the official UCI PhiUSIIL Phishing URL dataset in `data/dataset.csv`; it has raw `URL` and `label` columns and is licensed CC BY 4.0. Its numeric labels use `0 = phishing`, `1 = legitimate`, matching the training default. When uploading another numeric dataset, select the correct phishing label from the admin dashboard after checking the source documentation. Text labels such as `phishing`/`legitimate` and `malicious`/`benign` are recognized without numeric mapping. No examples are fabricated.

An administrator can upload a CSV on **Admin overview** and select **Train and evaluate models**. Alternatively, train the included UCI dataset with `python train_model.py data\dataset.csv`; use `--numeric-phishing-label 1` for datasets where numeric label 1 means phishing. Training rejects malformed/empty datasets and requires at least three unique valid URLs per class for a stratified split. The dashboard reports discarded records and saves the selected model to `data/models/phishing_url_model.joblib`.

## Analyze URLs

Sign in, open **Check a URL**, and enter a full HTTP(S) URL or a domain name. The app does not open the URL. The result includes its prediction, selected model, and predicted-class confidence when the classifier supports probabilities. Every successful prediction is stored in your own history.

## History, reports, and evaluation

- **Overview** shows your counts and latest checks.
- **Detection history** shows only your account's records.
- **Reports** downloads only your own detection history as CSV.
- **Model performance** displays both model comparisons, the selected classifier's confusion matrix and classification report, and held-out evaluation metadata.

Predictions are not guarantees. A site marked legitimate can still be dangerous; use independent security checks and never enter sensitive information based only on this tool.

## Administrator tools

The admin overview displays enabled/disabled account counts, aggregate usage, recent detection activity, and accepts a training CSV. **Users & accounts** shows registered user profiles, roles, account status, registration date, and detection counts. Administrators can change roles and enable or disable other accounts from this page. Disabled users cannot log in; an already-signed-in user is signed out on their next app request. The current administrator cannot change their own account from this page, and the final enabled administrator cannot be demoted or disabled.
