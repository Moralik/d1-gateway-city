#!/usr/bin/env python3
"""Девять проверок ЛР4 с реальным брокером и изолированными данными."""

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bus.consumer import INCOMING_TOPIC, INCOMING_TYPE, SOC_SOURCE, SUBSCRIBER
from bus.producer import GATEWAY_SOURCE, OUTGOING_TOPIC, OUTGOING_TYPE, GatewayBus, build_event
from bus.sign import sign, verify
from bus.store import connect
from privacy import Boundary
from privacy.pseudonym import SALT_ENV

SOC_SUBSCRIBER = "d8-soc"


def utc_stamp(moment=None):
    return (moment or datetime.now(UTC)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def wait_for_output(process, output, prefix):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        for line in output.read_text(encoding="utf-8").splitlines():
            if line.startswith(prefix):
                return line.removeprefix(prefix)
        if process.poll() is not None:
            break
        time.sleep(0.05)
    raise RuntimeError(output.read_text(encoding="utf-8").strip() or f"нет сообщения «{prefix}»")


@contextmanager
def child_process(command, output, environment):
    with output.open("wb") as stream:
        process = subprocess.Popen(command, cwd=ROOT, env={**environment, "PYTHONIOENCODING": "utf-8"},
                                   stdin=subprocess.PIPE, stdout=stream, stderr=subprocess.STDOUT)
        try:
            yield process
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stdin.close()


@contextmanager
def broker(directory, port="0"):
    output = directory / "broker.log"
    command = [sys.executable, str(ROOT / "services/broker/local_broker.py")]
    environment = {**os.environ, "BROKER_HOST": "127.0.0.1", "BROKER_PORT": port,
                   "BROKER_DB": str(directory / "broker.sqlite3")}
    with child_process(command, output, environment) as process:
        yield wait_for_output(process, output, "Учебный брокер: ")


def make_bus(directory, broker_url, keys, log):
    boundary = Boundary(ROOT / "config/privacy.toml", directory / "vault.sqlite3")
    return GatewayBus(directory / "gateway.sqlite3", broker_url, *keys, boundary.filter_event, log)


def incident_event(key, moment=None):
    incident_id = str(uuid4())
    event = build_event(INCOMING_TYPE,
                        {"incident_id": incident_id, "target_district": "gateway", "severity": "high"},
                        SOC_SOURCE, subject=incident_id)
    event["time"] = utc_stamp(moment)
    sign(event, key)
    return event


def soc_receive(bus, publish_key, event_id):
    messages = bus.broker.poll(SOC_SUBSCRIBER, OUTGOING_TOPIC)
    if len(messages) != 1 or messages[0]["event"]["id"] != event_id:
        raise RuntimeError("SOC ожидал одну доставку созданного события")
    event = messages[0]["event"]
    if verify(event, publish_key):
        bus.broker.ack(OUTGOING_TOPIC, event_id, SOC_SUBSCRIBER)
    return event


def protocol_signature(event, key):
    """Независимый расчёт ожидаемого citysig по Р5."""
    data = json.dumps(event["data"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
    signed = f"{event['type']}\n{event['id']}\n{event['time']}\n{digest}"
    return hmac.new(key, signed.encode("utf-8"), hashlib.sha256).hexdigest()


def valid_envelope(event):
    required = {"specversion", "id", "source", "type", "time", "subject", "datacontenttype", "data", "citysig"}
    return (required <= event.keys() and event["specversion"] == "1.0"
            and str(UUID(event["id"])) == event["id"]
            and event["type"] == OUTGOING_TYPE and event["source"] == GATEWAY_SOURCE
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", event["time"])
            and datetime.fromisoformat(event["time"]).utcoffset() == timedelta(0)
            and event["datacontenttype"] == "application/json" and isinstance(event["data"], dict)
            and event["subject"] == event["data"].get("block_id"))


def no_effect(bus, event):
    with connect(bus.db_path) as db:
        handled = db.execute("SELECT 1 FROM processed WHERE event_id = ?", (event["id"],)).fetchone()
        incident = db.execute("SELECT 1 FROM incidents WHERE incident_id = ?",
                              (event["data"]["incident_id"],)).fetchone()
    return handled is None and incident is None


def handled_once(bus, event):
    with connect(bus.db_path) as db:
        handled = db.execute("SELECT COUNT(*) FROM processed WHERE event_id = ?", (event["id"],)).fetchone()[0]
        incident = db.execute("SELECT severity FROM incidents WHERE incident_id = ?",
                              (event["data"]["incident_id"],)).fetchall()
    return handled == 1 and incident == [(event["data"]["severity"],)]


def rejection(bus, event, reason, logs):
    bus.broker.publish(INCOMING_TOPIC, event)
    result = bus.poll()
    return (result == [reason] and logs[-1] == ("event.rejected", {"reason": reason})
            and no_effect(bus, event) and not bus.broker.poll(SUBSCRIBER, INCOMING_TOPIC))


def pause_before_dispatch(directory, broker_url, event_id):
    keys = (bytes.fromhex(os.environ["CHECK_BUS_PUBLISH_KEY"]), bytes.fromhex(os.environ["CHECK_BUS_CONSUME_KEY"]))
    bus = make_bus(directory, broker_url, keys, lambda *args, **kwargs: None)

    def pause(event, topic):
        if event["id"] != event_id or topic != INCOMING_TOPIC:
            raise RuntimeError("получено неожиданное сообщение")
        print(f"Получено: {event_id}", flush=True)
        sys.stdin.read(1)
        raise RuntimeError("проба остановилась до обработки")

    bus.consumer.process = pause
    bus.poll()
    raise RuntimeError("сообщение не получено")


def crash_before_dispatch(directory, broker_url, keys, event_id):
    command = [sys.executable, str(Path(__file__).resolve()), "--pause-before-dispatch", str(directory),
               broker_url, event_id]
    environment = {**os.environ, "CHECK_BUS_PUBLISH_KEY": keys[0].hex(), "CHECK_BUS_CONSUME_KEY": keys[1].hex()}
    output = directory / "consumer.log"
    with child_process(command, output, environment) as process:
        if wait_for_output(process, output, "Получено: ") != event_id:
            raise RuntimeError("дочерний консьюмер не подтвердил получение из брокера")
        # Контекст принудительно завершает процесс, пока обработчик ждёт в дочернем процессе.


def outbox_has(bus, event_id):
    with connect(bus.db_path) as db:
        return db.execute("SELECT 1 FROM outbox WHERE event_id = ?", (event_id,)).fetchone() is not None


def recovery_has_sections():
    path = ROOT / "docs/recovery.md"
    if not path.is_file():
        return False
    headings = re.findall(r"^#{1,6}\s+(.+)$", path.read_text(encoding="utf-8"), flags=re.MULTILINE)
    content = "\n".join(headings).casefold()
    return all(heading in content for heading in ("зависимости", "секреты", "порядок запуска", "проверка после восстановления"))


def run(directory):
    os.environ[SALT_ENV] = secrets.token_hex(32)
    keys = (secrets.token_bytes(32), secrets.token_bytes(32))
    publish_key, consume_key = keys
    checks = []
    logs = []

    def check(title, passed):
        checks.append(bool(passed))
        print(f"[{'OK' if passed else 'FAIL'}] {len(checks)}. {title}", flush=True)

    def log(level, event, outcome, msg, **fields):
        logs.append((event, fields.get("details")))

    with broker(directory) as url:
        bus = make_bus(directory, url, keys, log)
        created = bus.add_block("192.0.2.20", "scan", private_fields={"actor_id": "demo-admin"})
        bus.flush()
        outgoing = soc_receive(bus, publish_key, created)
        check("исходящий конверт CloudEvents, UUID, тип и время UTC", valid_envelope(outgoing))
        check("подпись исходящего события совпадает с расчётом по Р5",
              verify(outgoing, publish_key) and outgoing["citysig"] == protocol_signature(outgoing, publish_key))

        tampered = incident_event(consume_key)
        tampered["data"]["severity"] = "critical"
        check("подмена data после подписи -> bad_signature", rejection(bus, tampered, "bad_signature", logs))
        check("подпись ключом другого направления -> bad_signature",
              rejection(bus, incident_event(publish_key), "bad_signature", logs))

        repeated = incident_event(consume_key)
        bus.broker.publish(INCOMING_TOPIC, repeated)
        delivery = bus.broker.poll(SUBSCRIBER, INCOMING_TOPIC)[0]
        # Эффект записался, подтверждение потерялось. Повтор получает сам консьюмер.
        first = bus.consumer.process(delivery["event"], delivery["topic"])
        second = bus.poll()
        check("повтор события -> duplicate, эффект сохранён один раз",
              first == "accepted" and second == ["duplicate"] and handled_once(bus, repeated)
              and not bus.broker.poll(SUBSCRIBER, INCOMING_TOPIC))

        stale = incident_event(consume_key, datetime.now(UTC) - timedelta(minutes=10))
        check("событие старше десяти минут -> stale", rejection(bus, stale, "stale", logs))

    outage_began = utc_stamp()
    event_id = bus.add_block("192.0.2.21", "policy")
    try:
        bus.flush()
    except OSError:
        kept_during_outage = outbox_has(bus, event_id)
    else:
        kept_during_outage = False
    print(f"  T1 {outage_began} — брокер остановлен, запись в очереди: {kept_during_outage}", flush=True)

    with broker(directory, url.rsplit(":", 1)[1]) as restarted_url:
        recovery_began = time.monotonic()
        print(f"  T2 {utc_stamp()} — брокер снова слушает", flush=True)
        bus = make_bus(directory, restarted_url, keys, log)
        published = bus.flush()
        delivered = soc_receive(bus, publish_key, event_id)
        check("после отказа очередь доставлена SOC один раз",
              kept_during_outage and published == 1 and verify(delivered, publish_key)
              and not outbox_has(bus, event_id) and bus.flush() == 0
              and not bus.broker.poll(SOC_SUBSCRIBER, OUTGOING_TOPIC))
        print(f"  T3 {utc_stamp()} — восстановление доставки за {time.monotonic() - recovery_began:.3f} с", flush=True)

        interrupted = incident_event(consume_key)
        bus.broker.publish(INCOMING_TOPIC, interrupted)
        crash_before_dispatch(directory, restarted_url, keys, interrupted["id"])
        before = no_effect(bus, interrupted)
        restarted = make_bus(directory, restarted_url, keys, log)
        first = restarted.poll()
        second = restarted.poll()
        check("падение консьюмера после получения -> обработка один раз после перезапуска",
              before and first == ["accepted"] and second == [] and handled_once(restarted, interrupted))

    check("docs/recovery.md содержит четыре раздела восстановления", recovery_has_sections())
    print(f"\nпройдено {sum(checks)} из 9")
    return 0 if len(checks) == 9 and all(checks) else 1


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--pause-before-dispatch":
        pause_before_dispatch(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    with tempfile.TemporaryDirectory(prefix="check-bus-") as temporary:
        raise SystemExit(run(Path(temporary)))
