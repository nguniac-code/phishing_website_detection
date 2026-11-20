import sqlite3
import tempfile
import unittest
from pathlib import Path

import auth
import database


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.previous_db_path = database.DB_PATH
        database.DB_PATH = Path(self.temp_dir.name) / "test.sqlite3"
        database.init_db()

    def tearDown(self):
        database.DB_PATH = self.previous_db_path
        self.temp_dir.cleanup()

    def test_password_hash_is_not_plaintext_and_verifies(self):
        hashed = auth.hash_password("correct horse battery")
        self.assertNotEqual(hashed, "correct horse battery")
        self.assertTrue(auth.verify_password("correct horse battery", hashed))
        self.assertFalse(auth.verify_password("wrong password", hashed))

    def test_registration_login_and_case_insensitive_account_lookup(self):
        user_id = auth.register_user(
            "Test User",
            "test_user",
            "test@example.com",
            "a strong password 123",
            "a strong password 123",
        )
        self.assertGreater(user_id, 0)
        user = auth.authenticate_user("TEST_USER", "a strong password 123")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "user")
        self.assertIsNone(auth.authenticate_user("test@example.com", "incorrect"))

    def test_duplicate_accounts_and_weak_password_are_rejected(self):
        details = ("Test User", "test_user", "test@example.com", "a strong password 123")
        auth.register_user(*details, details[3])
        with self.assertRaisesRegex(ValueError, "already registered"):
            auth.register_user(*details, details[3])
        with self.assertRaisesRegex(ValueError, "10 characters"):
            auth.register_user("Another User", "another", "another@example.com", "short", "short")

    def test_role_changes_protect_last_admin_and_history_is_user_scoped(self):
        user_id = auth.register_user(
            "Test User",
            "test_user",
            "test@example.com",
            "a strong password 123",
            "a strong password 123",
        )
        admin_id = database.create_user(
            "Admin User",
            "admin_user",
            "admin@example.com",
            auth.hash_password("another strong password"),
            role="admin",
        )
        database.change_user_role(user_id, "admin")
        database.change_user_role(admin_id, "user")
        with self.assertRaisesRegex(ValueError, "last administrator"):
            database.change_user_role(user_id, "user")

        database.record_detection(user_id, "https://user.example", "legitimate", 0.9, "Random Forest")
        database.record_detection(admin_id, "https://admin.example", "phishing", 0.8, "Random Forest")
        self.assertEqual(
            [row["url"] for row in database.get_detections(user_id)],
            ["https://user.example"],
        )
        self.assertEqual(
            [row["url"] for row in database.get_detections(admin_id)],
            ["https://admin.example"],
        )

    def test_disabled_accounts_cannot_authenticate_and_can_be_reenabled(self):
        user_id = auth.register_user(
            "Test User",
            "test_user",
            "test@example.com",
            "a strong password 123",
            "a strong password 123",
        )
        self.assertIsNotNone(auth.authenticate_user("test_user", "a strong password 123"))
        database.set_user_active(user_id, False)
        self.assertIsNone(auth.authenticate_user("test_user", "a strong password 123"))
        self.assertEqual(database.get_admin_stats()["disabled_users"], 1)

        database.set_user_active(user_id, True)
        self.assertIsNotNone(auth.authenticate_user("test_user", "a strong password 123"))
        self.assertEqual(database.get_admin_stats()["active_users"], 1)

    def test_last_enabled_admin_cannot_be_disabled(self):
        admin_id = database.create_user(
            "Admin User",
            "admin_user",
            "admin@example.com",
            auth.hash_password("another strong password"),
            role="admin",
        )
        with self.assertRaisesRegex(ValueError, "last enabled administrator"):
            database.set_user_active(admin_id, False)

    def test_existing_database_is_migrated_with_enabled_accounts(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.sqlite3"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user'
                        CHECK (role IN ('user', 'admin')),
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
                """
            )
            connection.execute(
                """
                INSERT INTO users (full_name, username, email, password_hash)
                VALUES (?, ?, ?, ?)
                """,
                ("Legacy User", "legacy_user", "legacy@example.com", "existing-hash"),
            )
            connection.commit()
        finally:
            connection.close()

        database.DB_PATH = legacy_path
        database.init_db()
        migrated_user = database.get_user_by_id(1)
        self.assertEqual(migrated_user["is_active"], 1)
        self.assertEqual(database.get_admin_stats()["active_users"], 1)


if __name__ == "__main__":
    unittest.main()
