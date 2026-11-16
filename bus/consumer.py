"""Приём инцидентов SOC: подпись, время, дедупликация, эффект, журнал и ack."""

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .sign import fresh, is_uuid, verify
from .store import connect
from .transport import Broker

INCOMING_TYPE = "city.soc.incident.opened.v1"
INCOMING_TOPIC = "city.events.soc.incident.opened"
SOC_SOURCE = "/d8-soc/api"
SUBSCRIBER = "d1-gateway"
SEVERITIES = {"low", "medium", "high", "critical"}


class Consumer:
    def __init__(self, db_path: Path, broker: Broker, key: bytes, log: Callable):
        self.db_path = db_path
        self.broker = broker
        self.key = key
        self.log = log

    def _reject(self, reason: str) -> str:
        self.log("WARN", "event.rejected", "failure", "событие отклонено", details={"reason": reason})
        return reason

    def _contract(self, event: dict, topic: str) -> bool:
        data = event.get("data")
        if not isinstance(data, dict) or set(data) - {"incident_id", "target_district", "severity"}:
            return False
        severity = data.get("severity", "medium")
        return (
            topic == INCOMING_TOPIC
            and event.get("type") == INCOMING_TYPE
            and event.get("source") == SOC_SOURCE
            and event.get("specversion") == "1.0"
            and event.get("datacontenttype") == "application/json"
            and is_uuid(data.get("incident_id"))
            and event.get("subject") == data["incident_id"]
            and data.get("target_district") == "gateway"
            and isinstance(severity, str) and severity in SEVERITIES
        )

    def process(self, event: dict, topic: str = INCOMING_TOPIC) -> str:
        if not verify(event, self.key):
            return self._reject("bad_signature")
        if not fresh(event):
            return self._reject("stale")
        event_id = event["id"]
        if not is_uuid(event_id):
            return self._reject("invalid_envelope")

        with connect(self.db_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM processed WHERE event_id = ?", (event_id,)).fetchone():
                return self._reject("duplicate")
            if not self._contract(event, topic):
                return self._reject("invalid_contract")

            data = event["data"]
            db.execute(
                "INSERT INTO incidents (incident_id, severity) VALUES (?, ?) ON CONFLICT DO NOTHING",
                (data["incident_id"], data.get("severity", "medium")),
            )
            db.execute("INSERT INTO processed VALUES (?, ?)", (event_id, datetime.now(UTC).isoformat()))

        self.log("INFO", "event.consumed", "success", "инцидент SOC учтён", details={"id": event_id})
        return "accepted"

    def poll(self) -> list[str]:
        results = []
        for message in self.broker.poll(SUBSCRIBER, INCOMING_TOPIC):
            event, topic = message["event"], message["topic"]
            results.append(self.process(event, topic))
            # Дубликаты и окончательно отклонённые сообщения также снимаются с доставки.
            self.broker.ack(topic, event["id"], SUBSCRIBER)
        return results
