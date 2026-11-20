# Database design

The application creates `data/phishing_detection.db` on first run. Set `PHISHING_DB_PATH` to use another local path. SQLite foreign-key enforcement is enabled for every connection.

## `users`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | INTEGER | Primary key |
| `full_name` | TEXT | Required display name |
| `username` | TEXT | Required, case-insensitive unique identifier |
| `email` | TEXT | Required, case-insensitive unique identifier |
| `password_hash` | TEXT | PBKDF2-HMAC-SHA256 encoded hash; never plaintext |
| `role` | TEXT | `user` or `admin`, defaults to `user` |
| `is_active` | INTEGER | `1` when enabled, `0` when disabled; defaults to enabled |
| `created_at` | TEXT | UTC creation timestamp |

## `detections`

| Column | Type | Constraints / purpose |
|---|---|---|
| `id` | INTEGER | Primary key |
| `user_id` | INTEGER | Required foreign key to `users.id`, cascades on account removal |
| `url` | TEXT | Normalized URL submitted for analysis |
| `result` | TEXT | `phishing` or `legitimate` |
| `confidence` | REAL | Optional predicted-class probability in `[0, 1]` |
| `model_name` | TEXT | Selected saved classifier |
| `created_at` | TEXT | UTC detection timestamp |

An index on `(user_id, created_at DESC)` supports user-scoped history queries. Detection history and report queries always filter by the authenticated account ID; administrators can review cross-account detection activity and account records. Existing databases are migrated on startup by adding the enabled-by-default `is_active` column. Disabled accounts cannot authenticate, and existing Streamlit sessions are ended on their next app request. The final enabled administrator cannot be disabled.
