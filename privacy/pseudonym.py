"""HMAC-псевдонимы и локальная таблица восстановления."""

import hashlib
import hmac
import os
import re
import sqlite3
import time
from contextlib import closing
from functools import lru_cache
from pathlib import Path

SALT_ENV = "PRIVACY_SALT"
RETENTION_SECONDS = 30 * 24 * 60 * 60


@lru_cache(maxsize=1)
def get_salt() -> bytes:
    raw = os.environ.get(SALT_ENV, "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
        raise RuntimeError("PRIVACY_SALT должна содержать 64 шестнадцатеричных символа")
    return bytes.fromhex(raw)


def pseudonym(field: str, value: str) -> str:
    message = f"{field}\n{value}".encode("utf-8")
    digest = hmac.new(get_salt(), message, hashlib.sha256).hexdigest()
    return "psn:" + digest[:32]


class Vault:
    """Хранит соответствия только в файловой системе района."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path or os.environ.get("PRIVACY_VAULT", "local/vault.sqlite3"))

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)

        if os.name == "posix":
            self.path.chmod(0o600)

        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS mappings (
                    field TEXT NOT NULL,
                    token TEXT NOT NULL,
                    value TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY(field, token)
                )"""
            )
        except Exception:
            connection.close()
            raise
        return connection

    def remember(self, rows: list[tuple[str, str, str]]) -> None:
        if not rows:
            return
        now = int(time.time())
        with closing(self._connect()) as db, db:
            db.execute("DELETE FROM mappings WHERE expires_at <= ?", (now,))
            for field, token, value in rows:
                result = db.execute(
                    """INSERT INTO mappings(field, token, value, expires_at) VALUES (?, ?, ?, ?)
                       ON CONFLICT(field, token) DO UPDATE SET expires_at = excluded.expires_at
                       WHERE mappings.value = excluded.value""",
                    (field, token, value, now + RETENTION_SECONDS),
                )
                if result.rowcount != 1:
                    raise RuntimeError("Коллизия псевдонимов")

    def restore(self, field: str, token: str) -> str | None:
        if not self.path.exists():
            return None
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT value FROM mappings WHERE field = ? AND token = ? AND expires_at > ?",
                (field, token, int(time.time())),
            ).fetchone()
        return row[0] if row else None

    def delete(self, field: str, value: str) -> int:
        if not self.path.exists():
            return 0
        with closing(self._connect()) as db, db:
            return db.execute("DELETE FROM mappings WHERE field = ? AND value = ?", (field, value)).rowcount

    def purge(self) -> int:
        if not self.path.exists():
            return 0
        with closing(self._connect()) as db, db:
            return db.execute("DELETE FROM mappings WHERE expires_at <= ?", (int(time.time()),)).rowcount


def restore(field: str, token: str, vault: Vault | None = None) -> str | None:
    return (vault or Vault()).restore(field, token)
