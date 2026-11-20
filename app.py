"""PhishGuard Streamlit application."""

from __future__ import annotations

import sqlite3

import matplotlib.pyplot as plt
import pandas as pd
import plotly.express as px
import streamlit as st

import auth
import database
from config import APP_TITLE, BASE_DIR
from prediction import predict_url
from train_model import load_model_artifact, train_models


st.set_page_config(
    page_title=APP_TITLE,
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def _apply_styles() -> None:
    stylesheet = BASE_DIR / "assets" / "style.css"
    if stylesheet.is_file():
        st.markdown(f"<style>{stylesheet.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)


def _render_brand() -> None:
    st.markdown(
        """
        <div class="brand">
            <div class="brand-mark">P</div>
            <div><div class="brand-name">PHISHGUARD</div>
            <div class="brand-caption">URL INTELLIGENCE PLATFORM</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _format_result(value: str) -> str:
    return "Phishing" if value == "phishing" else "Legitimate"


def _render_authentication() -> None:
    _render_brand()
    st.markdown(
        '<div class="eyebrow">SECURITY STARTS WITH A CHECK</div>'
        '<h1 class="page-title">Welcome to PhishGuard</h1>'
        '<p class="page-subtitle">A machine-learning workspace for safer URL decisions.</p>',
        unsafe_allow_html=True,
    )
    login_tab, register_tab = st.tabs(["Sign in", "Create account"])

    with login_tab:
        with st.form("login_form"):
            identifier = st.text_input("Username or email", autocomplete="username")
            password = st.text_input("Password", type="password", autocomplete="current-password")
            submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)
        if submitted:
            if not identifier.strip() or not password:
                st.error("Enter your username or email and password.")
            else:
                user = auth.authenticate_user(identifier, password)
                if user is None:
                    st.error("Sign-in failed. Check your credentials or contact an administrator if your account is disabled.")
                else:
                    st.session_state["user_id"] = user["id"]
                    st.rerun()

    with register_tab:
        with st.form("register_form"):
            full_name = st.text_input("Full name", max_chars=100)
            username = st.text_input("Username", max_chars=32, autocomplete="username")
            email = st.text_input("Email address", max_chars=254, autocomplete="email")
            new_password = st.text_input(
                "Password (at least 10 characters)",
                type="password",
                autocomplete="new-password",
            )
            confirm_password = st.text_input(
                "Confirm password",
                type="password",
                autocomplete="new-password",
            )
            submitted = st.form_submit_button(
                "Create account", type="primary", use_container_width=True
            )
        if submitted:
            try:
                user_id = auth.register_user(
                    full_name, username, email, new_password, confirm_password
                )
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.session_state["user_id"] = user_id
                st.success("Your account is ready.")
                st.rerun()

    st.caption(
        "Administrator accounts are provisioned by an operator with "
        "`python auth.py create-admin`; public registration always creates a standard user."
    )


def _render_missing_model() -> bool:
    try:
        load_model_artifact()
    except FileNotFoundError:
        st.info(
            "The application is ready, but URL classification is not enabled until a model "
            "has been trained from a labeled dataset. An administrator can train one from "
            "the Admin overview, or use `python train_model.py path\\to\\dataset.csv`."
        )
        return False
    return True


def _render_overview(user: dict) -> None:
    st.markdown('<div class="eyebrow">PERSONAL WORKSPACE</div>', unsafe_allow_html=True)
    st.title(f"Good to see you, {user['full_name']}")
    st.markdown(
        '<p class="page-subtitle">Review your URL activity and make a new assessment.</p>',
        unsafe_allow_html=True,
    )
    stats = database.get_user_stats(user["id"])
    columns = st.columns(3)
    columns[0].metric("URLs checked", stats["total"])
    columns[1].metric("Phishing flagged", stats["phishing"])
    columns[2].metric("Legitimate", stats["legitimate"])

    left, right = st.columns([1.3, 1])
    with left:
        st.subheader("Recent detection activity")
        records = database.get_detections(user["id"], limit=8)
        if records:
            frame = pd.DataFrame(records)
            frame["result"] = frame["result"].map(_format_result)
            frame["created_at"] = pd.to_datetime(frame["created_at"], utc=True).dt.strftime(
                "%Y-%m-%d %H:%M UTC"
            )
            st.dataframe(
                frame[["created_at", "url", "result", "model_name"]],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.markdown(
                '<div class="empty-state">No checks yet. Start with a URL you want to assess.</div>',
                unsafe_allow_html=True,
            )
    with right:
        st.subheader("Your activity mix")
        if stats["total"]:
            chart_data = pd.DataFrame(
                {"Result": ["Phishing", "Legitimate"], "URLs": [stats["phishing"], stats["legitimate"]]}
            )
            chart_data = chart_data[chart_data["URLs"] > 0]
            figure = px.pie(
                chart_data,
                names="Result",
                values="URLs",
                hole=0.68,
                color="Result",
                color_discrete_map={"Phishing": "#f15b64", "Legitimate": "#33c99a"},
            )
            figure.update_layout(
                margin=dict(t=10, b=10, l=0, r=0),
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#dce8f4",
                legend_title_text="",
            )
            st.plotly_chart(figure, use_container_width=True)
        else:
            st.markdown(
                '<div class="empty-state">Your chart will appear after your first URL check.</div>',
                unsafe_allow_html=True,
            )
    _render_missing_model()


def _render_detection(user: dict) -> None:
    st.markdown('<div class="eyebrow">URL ANALYSIS</div><h1 class="page-title">Check a website</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="page-subtitle">The URL is analyzed locally using the currently trained model. '
        'PhishGuard does not visit or open the submitted website.</p>',
        unsafe_allow_html=True,
    )
    with st.form("url_detection_form"):
        url = st.text_input("Website URL", placeholder="https://example.com")
        submitted = st.form_submit_button("Analyze URL", type="primary")
    if not submitted:
        return
    if not url.strip():
        st.error("Enter a website URL to analyze.")
        return
    try:
        result = predict_url(url)
        database.record_detection(
            user["id"],
            result["url"],
            result["result"],
            result["confidence"],
            result["model_name"],
        )
    except (ValueError, FileNotFoundError, OSError) as exc:
        st.error(str(exc))
        return

    if result["result"] == "phishing":
        st.error("Potential phishing URL")
        st.warning("Do not enter passwords, payment information, or other sensitive data on this site.")
    else:
        st.success("Classified as legitimate by the trained model")
    st.code(result["url"], language=None)
    details = st.columns(3)
    details[0].metric("Prediction", _format_result(result["result"]))
    details[1].metric(
        "Model confidence",
        f"{result['confidence']:.1%}" if result["confidence"] is not None else "Not available",
    )
    details[2].metric("Model", result["model_name"])
    st.caption("A model prediction is an indicator, not a guarantee of website safety.")


def _render_history(user: dict) -> None:
    st.markdown('<div class="eyebrow">YOUR RECORDS</div><h1 class="page-title">Detection history</h1>', unsafe_allow_html=True)
    records = database.get_detections(user["id"])
    if not records:
        st.info("Your detection history is empty.")
        return
    frame = pd.DataFrame(records)
    frame["result"] = frame["result"].map(_format_result)
    frame["confidence"] = frame["confidence"].map(
        lambda value: f"{value:.1%}" if pd.notna(value) else "Unavailable"
    )
    frame["created_at"] = pd.to_datetime(frame["created_at"], utc=True).dt.strftime(
        "%Y-%m-%d %H:%M UTC"
    )
    st.dataframe(frame, use_container_width=True, hide_index=True)


def _render_reports(user: dict) -> None:
    st.markdown('<div class="eyebrow">EXPORT CENTER</div><h1 class="page-title">Your reports</h1>', unsafe_allow_html=True)
    records = database.get_detections(user["id"])
    if not records:
        st.info("Complete a URL check first; your personal report will appear here.")
        return
    frame = pd.DataFrame(records)
    csv_bytes = frame.to_csv(index=False).encode("utf-8")
    st.metric("Records in report", len(frame))
    st.download_button(
        "Download detection history (CSV)",
        data=csv_bytes,
        file_name="phishguard_detection_history.csv",
        mime="text/csv",
        type="primary",
    )
    st.caption("This report contains only your account's detection records.")
    st.dataframe(frame, use_container_width=True, hide_index=True)


def _render_model_performance() -> None:
    st.markdown('<div class="eyebrow">MODEL QUALITY</div><h1 class="page-title">Model performance</h1>', unsafe_allow_html=True)
    try:
        artifact = load_model_artifact()
    except FileNotFoundError:
        st.info("No trained model is available. Train a model from a labeled CSV to view evaluation results.")
        return
    metrics = artifact["metrics"]
    metric_frame = pd.DataFrame(
        [
            {"Model": name, **{key.replace("_", " ").title(): result[key] for key in ("accuracy", "precision", "recall", "f1_score")}}
            for name, result in metrics.items()
        ]
    )
    chart = px.bar(
        metric_frame.melt(id_vars="Model", var_name="Metric", value_name="Score"),
        x="Metric",
        y="Score",
        color="Model",
        barmode="group",
        range_y=[0, 1],
        color_discrete_sequence=["#43d9b2", "#718cff"],
    )
    chart.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#dce8f4",
        margin=dict(t=20, b=20),
        yaxis_tickformat=".0%",
    )
    st.plotly_chart(chart, use_container_width=True)
    st.success(f"Selected model: {artifact['model_name']} · selection based on phishing-class F1-score.")

    selected_metrics = artifact["selected_metrics"]
    matrix = selected_metrics["confusion_matrix"]
    figure, axis = plt.subplots(figsize=(5.4, 4))
    image = axis.imshow(matrix, cmap="Blues")
    axis.set(
        xticks=[0, 1],
        yticks=[0, 1],
        xticklabels=["Legitimate", "Phishing"],
        yticklabels=["Legitimate", "Phishing"],
        xlabel="Predicted label",
        ylabel="True label",
        title="Selected model · confusion matrix",
    )
    for row in range(2):
        for column in range(2):
            axis.text(column, row, str(matrix[row][column]), ha="center", va="center", color="#12243a")
    figure.colorbar(image, ax=axis, fraction=0.046, pad=0.04)
    figure.tight_layout()
    st.pyplot(figure, clear_figure=True)
    plt.close(figure)

    report = pd.DataFrame(selected_metrics["classification_report"]).transpose()
    st.subheader("Classification report")
    st.dataframe(report.style.format(precision=3), use_container_width=True)
    st.caption(
        f"Evaluated on {artifact['test_size']} held-out records, stratified from "
        f"{artifact['dataset_summary']['valid_rows']} unique valid URLs. "
        f"Trained: {artifact['trained_at']}."
    )


def _render_admin_overview() -> None:
    st.markdown('<div class="eyebrow">ADMINISTRATION</div><h1 class="page-title">Admin overview</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="page-subtitle">View registered accounts, manage access, and monitor platform activity.</p>',
        unsafe_allow_html=True,
    )
    stats = database.get_admin_stats()
    columns = st.columns(5)
    columns[0].metric("Registered users", stats["users"])
    columns[1].metric("Enabled accounts", stats["active_users"])
    columns[2].metric("Disabled accounts", stats["disabled_users"])
    columns[3].metric("All URL checks", stats["detections"])
    columns[4].metric("Phishing flagged", stats["phishing"])

    st.subheader("Monitor URL detection activity")
    activity_filter = st.selectbox(
        "Activity result",
        ["All results", "Phishing", "Legitimate"],
        key="admin_activity_filter",
    )
    activity = database.get_recent_admin_activity(limit=100)
    if activity_filter != "All results":
        expected_result = activity_filter.lower()
        activity = [row for row in activity if row["result"] == expected_result]
    if activity:
        activity_frame = pd.DataFrame(activity)
        activity_frame["result"] = activity_frame["result"].map(_format_result)
        activity_frame["confidence"] = activity_frame["confidence"].map(
            lambda value: f"{value:.1%}" if pd.notna(value) else "Unavailable"
        )
        activity_frame["created_at"] = pd.to_datetime(
            activity_frame["created_at"], utc=True
        ).dt.strftime("%Y-%m-%d %H:%M UTC")
        st.dataframe(
            activity_frame[
                ["created_at", "full_name", "username", "url", "result", "confidence", "model_name"]
            ],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No URL detection activity matches this filter.")
    st.caption("Open **Users & accounts** from the admin sidebar to manage account access.")

    st.subheader("Train or replace the detection model")
    st.markdown(
        "Upload a labeled CSV with a URL column and a label column. "
        "The model is evaluated on a stratified holdout set and the better classifier is saved."
    )
    upload = st.file_uploader(
        "Labeled URL dataset (CSV)",
        type=["csv"],
        max_upload_size=100,
        help="Accepts phishing/legitimate text labels or numeric 0/1 labels. Confirm the source legend.",
    )
    numeric_phishing_label = st.radio(
        "For numeric labels, which value means phishing?",
        options=[0, 1],
        format_func=lambda value: (
            f"{value} = phishing, {1 - value} = legitimate"
            + (" (UCI PhiUSIIL default)" if value == 0 else "")
        ),
        horizontal=True,
    )
    if upload is not None:
        st.caption(f"Selected: {upload.name} · {upload.size:,} bytes")
        if st.button("Train and evaluate models", type="primary"):
            try:
                with st.spinner("Validating URLs and training both classifiers…"):
                    artifact = train_models(
                        upload.getvalue(),
                        numeric_phishing_label=numeric_phishing_label,
                    )
            except (ValueError, OSError) as exc:
                st.error(f"Training failed: {exc}")
            else:
                st.success(
                    f"{artifact['model_name']} saved. "
                    f"Phishing F1: {artifact['selected_metrics']['f1_score']:.3f}."
                )
                st.json(artifact["dataset_summary"])

    st.caption(
        "Dataset records are processed for training but are not stored by the dashboard. "
        "The evaluated model artifact is stored locally."
    )


def _render_user_management(current_user: dict) -> None:
    st.markdown('<div class="eyebrow">ACCESS CONTROL</div><h1 class="page-title">User management</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="page-subtitle">View registered users, manage account roles, and enable or disable access.</p>',
        unsafe_allow_html=True,
    )
    users = database.list_users()
    if not users:
        st.info("No accounts are registered.")
        return
    frame = pd.DataFrame(users)
    frame["account_status"] = frame["is_active"].map(
        {1: "Enabled", 0: "Disabled", True: "Enabled", False: "Disabled"}
    )
    frame = frame.drop(columns=["is_active"])
    st.dataframe(frame, use_container_width=True, hide_index=True)

    editable_users = [user for user in users if user["id"] != current_user["id"]]
    if not editable_users:
        st.caption("There are no other accounts to manage.")
        return
    selected_id = st.selectbox(
        "Account",
        options=[user["id"] for user in editable_users],
        format_func=lambda user_id: next(
            f"{user['full_name']} (@{user['username']}) — {user['role']} — "
            f"{'enabled' if user['is_active'] else 'disabled'}"
            for user in editable_users
            if user["id"] == user_id
        ),
    )
    selected_user = next(user for user in editable_users if user["id"] == selected_id)
    current_role = selected_user["role"]
    with st.form("role_form"):
        new_role = st.selectbox(
            "Role",
            ["user", "admin"],
            index=["user", "admin"].index(current_role),
        )
        submitted = st.form_submit_button("Save role")
    if submitted:
        try:
            database.change_user_role(selected_id, new_role)
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.success("Account role updated.")
            st.rerun()

    action = "Disable account" if selected_user["is_active"] else "Enable account"
    with st.form("account_status_form"):
        st.caption(
            f"Current status: {'Enabled' if selected_user['is_active'] else 'Disabled'}. "
            "Disabled accounts cannot sign in; active sessions are ended on their next app request."
        )
        status_submitted = st.form_submit_button(
            action,
            type="primary" if not selected_user["is_active"] else "secondary",
        )
    if status_submitted:
        try:
            database.set_user_active(selected_id, not bool(selected_user["is_active"]))
        except ValueError as exc:
            st.error(str(exc))
        else:
            st.success(f"Account {('enabled' if not selected_user['is_active'] else 'disabled')}.")
            st.rerun()

def _render_app(user: dict) -> None:
    is_admin = user["role"] == "admin"
    pages = ["Overview", "Check a URL", "Detection history", "Reports", "Model performance"]
    if is_admin:
        pages.extend(["Admin overview", "Users & accounts"])
    with st.sidebar:
        _render_brand()
        st.markdown(f"Signed in as **{user['full_name']}**")
        st.caption(f"Role: {user['role'].title()}")
        page = st.radio("Workspace", pages, label_visibility="collapsed")
        st.divider()
        if st.button("Sign out", use_container_width=True):
            st.session_state.pop("user_id", None)
            st.rerun()
        st.caption("Predictions are model-based and should be treated as risk signals.")

    if page == "Overview":
        _render_overview(user)
    elif page == "Check a URL":
        _render_detection(user)
    elif page == "Detection history":
        _render_history(user)
    elif page == "Reports":
        _render_reports(user)
    elif page == "Model performance":
        _render_model_performance()
    elif page == "Admin overview" and is_admin:
        _render_admin_overview()
    elif page == "Users & accounts" and is_admin:
        _render_user_management(user)
    else:
        st.error("You do not have permission to access this page.")


def main() -> None:
    _apply_styles()
    try:
        database.init_db()
    except sqlite3.Error as exc:
        st.error(f"Unable to initialize the application database: {exc}")
        st.stop()

    user_id = st.session_state.get("user_id")
    if user_id is None:
        _render_authentication()
        return
    user = database.get_user_by_id(int(user_id))
    if user is None or not user["is_active"]:
        st.session_state.pop("user_id", None)
        if user is not None:
            if user is not None:
                st.info("This account has been disabled. Contact an administrator for assistance.")
            _render_authentication()
            return
    _render_app(user)


if __name__ == "__main__":
    main()