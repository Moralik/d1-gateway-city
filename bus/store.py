"""Локальные транзакции правила, очереди и входящих событий."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def connect(path: Path):
    connection = sqlite3.connect(path, timeout=5)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL").fetchone()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS blocks (
                source TEXT PRIMARY KEY,
                block_id TEXT NOT NULL,
                reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS outbox (
                event_id TEXT PRIMARY KEY,
                event TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS processed (
                event_id TEXT PRIMARY KEY,
                processed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                severity TEXT NOT NULL
            );
        """)
