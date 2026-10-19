import sqlite3

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db_path = current_app.config["DATABASE"]
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_e: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    db.commit()


def create_user(username: str, password_hash: str) -> int:
    db = get_db()
    cursor = db.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash),
    )
    db.commit()
    return cursor.lastrowid  # type: ignore


def get_user_by_username(username: str) -> sqlite3.Row | None:
    db = get_db()
    cursor = db.execute(
        "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
        (username,),
    )
    return cursor.fetchone()


def get_user_by_id(user_id: int) -> sqlite3.Row | None:
    db = get_db()
    cursor = db.execute(
        "SELECT id, username, password_hash, created_at FROM users WHERE id = ?",
        (user_id,),
    )
    return cursor.fetchone()
