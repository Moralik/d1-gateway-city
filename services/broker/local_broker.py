"""Локальный HTTP-брокер, совместимый с маршрутом доставки city-bus-kit."""

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

TOPIC = re.compile(r"city\.events\.[a-zA-Z0-9.]{1,90}")
IDENTIFIER = re.compile(r"[a-zA-Z0-9._-]{1,100}")
MAX_BODY = 64 * 1024


def matches(value: object, pattern: re.Pattern) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL").fetchone()
            db.executescript("""
                CREATE TABLE IF NOT EXISTS messages (
                    topic TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    event TEXT NOT NULL,
                    PRIMARY KEY (topic, event_id)
                );
                CREATE TABLE IF NOT EXISTS acks (
                    topic TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    subscriber TEXT NOT NULL,
                    PRIMARY KEY (topic, event_id, subscriber),
                    FOREIGN KEY (topic, event_id) REFERENCES messages (topic, event_id)
                );
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            with db:
                yield db
        finally:
            db.close()

    def publish(self, topic: str, event: dict) -> bool:
        body = json.dumps(event, ensure_ascii=False, allow_nan=False)
        with self.connect() as db:
            return db.execute(
                "INSERT INTO messages VALUES (?, ?, ?) ON CONFLICT DO NOTHING", (topic, event["id"], body),
            ).rowcount == 1

    def poll(self, sub: str, topic: str | None) -> list[dict]:
        with self.connect() as db:
            messages = db.execute("""
                SELECT m.topic, m.event FROM messages AS m
                WHERE (? IS NULL OR m.topic = ?)
                  AND NOT EXISTS (
                    SELECT 1 FROM acks AS a
                    WHERE a.topic = m.topic AND a.event_id = m.event_id AND a.subscriber = ?
                  )
                ORDER BY m.rowid LIMIT 100
                """, (topic, topic, sub)).fetchall()
        return [{"topic": name, "event": json.loads(body)} for name, body in messages]

    def ack(self, topic: str, event_id: str, sub: str) -> bool:
        with self.connect() as db:
            db.execute("""
                INSERT INTO acks (topic, event_id, subscriber)
                SELECT topic, event_id, ? FROM messages WHERE topic = ? AND event_id = ?
                ON CONFLICT DO NOTHING
                """, (sub, topic, event_id))
            return db.execute(
                "SELECT 1 FROM acks WHERE topic = ? AND event_id = ? AND subscriber = ?", (topic, event_id, sub),
            ).fetchone() is not None


class Handler(BaseHTTPRequestHandler):
    timeout = 10

    def log_message(self, *args):
        pass

    def _reply(self, status: int, value: dict) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        if url.path == "/health":
            self._reply(200, {"status": "ok"})
        elif url.path == "/poll":
            args = parse_qs(url.query)
            sub, topic = args.get("sub", ["anon"])[0], args.get("topic", [None])[0]
            if not matches(sub, IDENTIFIER) or (topic is not None and not matches(topic, TOPIC)):
                self._reply(400, {"error": "invalid subscriber or topic"})
                return
            self._reply(200, {"messages": self.server.store.poll(sub, topic)})
        else:
            self._reply(404, {"error": "not found"})

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not 0 < length <= MAX_BODY:
            raise ValueError("invalid body length")
        body = json.loads(self.rfile.read(length))
        if not isinstance(body, dict):
            raise ValueError("invalid body")
        return body

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in {"/publish", "/ack"}:
            self._reply(404, {"error": "not found"})
            return
        try:
            body = self._read_body()
            topic = body.get("topic")
            if not matches(topic, TOPIC):
                raise ValueError("invalid topic")
            if path == "/publish":
                event = body.get("event")
                if not isinstance(event, dict) or not matches(event.get("id"), IDENTIFIER):
                    raise ValueError("invalid event")
                inserted = self.server.store.publish(topic, event)
                self._reply(202, {"accepted": True, "duplicate": not inserted, "id": event["id"]})
            else:
                event_id, sub = body.get("id"), body.get("sub", "anon")
                if not matches(event_id, IDENTIFIER) or not matches(sub, IDENTIFIER):
                    raise ValueError("invalid event ID or subscriber")
                self._reply(200, {"acked": self.server.store.ack(topic, event_id, sub)})
        except (RecursionError, ValueError):
            self._reply(400, {"error": "invalid message"})
        except sqlite3.Error:
            self._reply(503, {"error": "broker storage unavailable"})


def main() -> None:
    host = os.environ.get("BROKER_HOST", "127.0.0.1")
    port = int(os.environ.get("BROKER_PORT", "14167"))
    db_path = Path(os.environ.get("BROKER_DB", "local/broker.sqlite3"))
    with ThreadingHTTPServer((host, port), Handler) as server:
        server.store = Store(db_path)
        print(f"Учебный брокер: http://{host}:{server.server_port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
