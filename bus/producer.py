"""Локальное правило блокировки и надёжная публикация событий Шлюза."""

import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from uuid import uuid4

from .consumer import Consumer
from .sign import canonical_json, sign
from .store import connect, initialize
from .transport import Broker

OUTGOING_TYPE = "city.gateway.block.added.v1"
OUTGOING_TOPIC = "city.events.gateway.block.added"
GATEWAY_SOURCE = "/d1-gateway/api"


def build_event(etype: str, data: dict, source: str, subject: str | None = None) -> dict:
    event_id = str(uuid4())
    return {
        "specversion": "1.0",
        "id": event_id,
        "source": source,
        "type": etype,
        "time": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "subject": subject or event_id,
        "datacontenttype": "application/json",
        "data": data,
    }


class GatewayBus:
    def __init__(self, db_path: Path, broker_url: str, publish_key: bytes, consume_key: bytes,
                 filter_event: Callable[[dict], dict], log: Callable):
        self.db_path = Path(db_path)
        initialize(self.db_path)
        self.broker = Broker(broker_url)
        self.publish_key = publish_key
        self.filter_event = filter_event
        self.log = log
        self.consumer = Consumer(self.db_path, self.broker, consume_key, log)

    def add_block(self, source: str, reason: str, request_id: str | None = None,
                  private_fields: dict | None = None) -> str | None:
        block_id = str(uuid4())
        data = {**(private_fields or {}), "block_id": block_id, "source": source, "reason_code": reason}
        draft = build_event(OUTGOING_TYPE, data, GATEWAY_SOURCE, block_id)
        event = self.filter_event(draft)
        sign(event, self.publish_key)

        with connect(self.db_path) as db:
            inserted = db.execute(
                "INSERT INTO blocks (source, block_id, reason) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                (event["data"]["source"], block_id, event["data"]["reason_code"]),
            )
            if inserted.rowcount == 0:
                return None
            db.execute("INSERT INTO outbox VALUES (?, ?)", (event["id"], canonical_json(event).decode("utf-8")))

        self.log("INFO", "event.queued", "success", "правило и событие сохранены",
                 request_id=request_id, details={"id": event["id"], "type": OUTGOING_TYPE})
        return event["id"]

    def is_blocked(self, source_alias: str) -> bool:
        with connect(self.db_path) as db:
            return db.execute("SELECT 1 FROM blocks WHERE source = ?", (source_alias,)).fetchone() is not None

    def flush(self) -> int:
        with connect(self.db_path) as db:
            pending = db.execute("SELECT event_id, event FROM outbox ORDER BY rowid LIMIT 100").fetchall()
        published = 0
        for event_id, encoded in pending:
            self.broker.publish(OUTGOING_TOPIC, json.loads(encoded))
            with connect(self.db_path) as db:
                removed = db.execute("DELETE FROM outbox WHERE event_id = ?", (event_id,)).rowcount
            if removed:
                published += 1
                self.log("INFO", "event.published", "success", "событие принято брокером",
                         details={"id": event_id, "type": OUTGOING_TYPE})
        return published

    def poll(self) -> list[str]:
        return self.consumer.poll()

    def run(self, stop_event: Event) -> None:
        unavailable = False
        while not stop_event.is_set():
            try:
                self.flush()
                self.poll()
            except (OSError, sqlite3.Error):
                if not unavailable:
                    self.log("WARN", "bus.unavailable", "failure", "обмен приостановлен, будет повтор")
                unavailable = True
            else:
                if unavailable:
                    self.log("INFO", "bus.available", "success", "обмен возобновлён")
                unavailable = False
            stop_event.wait(0.5)
