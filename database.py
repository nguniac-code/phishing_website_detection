"""SQLite persistence for accounts and URL detection history."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from config import DB_PATH


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
                    CHECK (role IN ('user', 'admin')),
                is_active INTEGER NOT NULL DEFAULT 1
                    CHECK (is_active IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );

            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                url TEXT NOT NULL,
                result TEXT NOT NULL CHECK (result IN ('phishing', 'legitimate')),
                confidence REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
                model_name TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );

            CREATE INDEX IF NOT EXISTS idx_detections_user_created
                ON detections(user_id, created_at DESC);
            """
        )
        user_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(users)")
        }
        if "is_active" not in user_columns:
            connection.execute(
                """
                ALTER TABLE users
                ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1
                    CHECK (is_active IN (0, 1))
                """
            )


def create_user(
    full_name: str,
    username: str,
    email: str,
    password_hash: str,
    role: str = "user",
) -> int:
    if role not in {"user", "admin"}:
        raise ValueError("Invalid account role.")
    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (full_name, username, email, password_hash, role)
                VALUES (?, ?, ?, ?, ?)
                """,
                (full_name.strip(), username.strip(), email.strip(), password_hash, role),
            )
            return int(cursor.lastrowid)
    except sqlite3.IntegrityError as exc:
        message = str(exc).lower()
        if "username" in message:
            raise ValueError("That username is already registered.") from exc
        if "email" in message:
            raise ValueError("That email address is already registered.") from exc
        raise


def get_user_by_identifier(identifier: str) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier.strip(), identifier.strip()),
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def record_detection(
    user_id: int,
    url: str,
    result: str,
    confidence: float | None,
    model_name: str,
) -> int:
    if result not in {"phishing", "legitimate"}:
        raise ValueError("Invalid detection result.")
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO detections (user_id, url, result, confidence, model_name)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, url, result, confidence, model_name),
        )
        return int(cursor.lastrowid)


def get_detections(user_id: int, limit: int | None = None) -> list[dict[str, Any]]:
    query = """
        SELECT id, url, result, confidence, model_name, created_at
        FROM detections WHERE user_id = ? ORDER BY created_at DESC, id DESC
    """
    parameters: tuple[Any, ...] = (user_id,)
    if limit is not None:
        query += " LIMIT ?"
        parameters = (user_id, max(0, int(limit)))
    with get_connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def get_user_stats(user_id: int) -> dict[str, int]:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN result = 'phishing' THEN 1 ELSE 0 END) AS phishing,
                   SUM(CASE WHEN result = 'legitimate' THEN 1 ELSE 0 END) AS legitimate
            FROM detections WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()
    return {key: int(row[key] or 0) for key in ("total", "phishing", "legitimate")}


def get_admin_stats() -> dict[str, int]:
    with get_connection() as connection:
        users = connection.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active,
                   SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) AS disabled
            FROM users
            """
        ).fetchone()
        detections = connection.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN result = 'phishing' THEN 1 ELSE 0 END) AS phishing
            FROM detections
            """
        ).fetchone()
    return {
        "users": int(users["total"] or 0),
        "active_users": int(users["active"] or 0),
        "disabled_users": int(users["disabled"] or 0),
        "detections": int(detections["total"] or 0),
        "phishing": int(detections["phishing"] or 0),
    }


def get_recent_admin_activity(limit: int = 20) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT d.id, u.full_name, u.username, d.url, d.result, d.confidence,
                   d.model_name, d.created_at
            FROM detections AS d
            JOIN users AS u ON u.id = d.user_id
            ORDER BY d.created_at DESC, d.id DESC
            LIMIT ?
            """,
            (max(0, int(limit)),),
        ).fetchall()
    return [dict(row) for row in rows]


def list_users() -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT u.id, u.full_name, u.username, u.email, u.role, u.is_active, u.created_at,
                   COUNT(d.id) AS detection_count
            FROM users AS u
            LEFT JOIN detections AS d ON d.user_id = u.id
            GROUP BY u.id
            ORDER BY u.created_at DESC, u.id DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def change_user_role(user_id: int, role: str) -> None:
    if role not in {"user", "admin"}:
        raise ValueError("Invalid account role.")
    with get_connection() as connection:
        current = connection.execute(
            "SELECT role FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if current is None:
            raise ValueError("User account no longer exists.")
        if current["role"] == "admin" and role != "admin":
            admin_count = connection.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin'"
            ).fetchone()[0]
            if admin_count <= 1:
                raise ValueError("The last administrator cannot be demoted.")
        connection.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))


def set_user_active(user_id: int, is_active: bool) -> None:
    if not isinstance(is_active, bool):
        raise ValueError("Account status must be enabled or disabled.")
    with get_connection() as connection:
        current = connection.execute(
            "SELECT role, is_active FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if current is None:
            raise ValueError("User account no longer exists.")
        if current["is_active"] == int(is_active):
            return
        if current["role"] == "admin" and not is_active:
            active_admins = connection.execute(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
            ).fetchone()[0]
            if active_admins <= 1:
                raise ValueError("The last enabled administrator cannot be disabled.")
        connection.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (int(is_active), user_id),
        )