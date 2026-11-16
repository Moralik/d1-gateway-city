"""HTTP API Шлюза и журнал JSON Lines (Р4)."""

import hmac
import ipaddress
import json
import os
import re
import sqlite3
import sys
import threading
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from bus.producer import GatewayBus
from privacy import Boundary, BoundaryError
from privacy.pseudonym import get_salt, pseudonym

DISTRICT = os.environ.get("DISTRICT", "unknown")
SERVICE = os.environ.get("SERVICE", "api")
PORT = int(os.environ.get("PORT", "8080"))
REASONS = {"abuse", "scan", "policy"}
REQUEST_ID = re.compile(r"[A-Za-z0-9-]{1,64}")
MAX_BODY = 4096


def log(level: str, event: str, outcome: str, msg: str, **fields: object) -> None:
    """Одна строка JSON в stdout: время UTC с миллисекундами (Р3) и обязательные поля Р4."""
    record = {
        "ts": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "district": DISTRICT,
        "service": SERVICE,
        "level": level,
        "event": event,
        "outcome": outcome,
        "msg": msg,
    }
    record.update({k: v for k, v in fields.items() if v is not None})
    print(json.dumps(record, ensure_ascii=False), file=sys.stdout, flush=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "city"  # не раскрываем версию Python в заголовке Server
    sys_version = ""
    timeout = 10

    def _begin(self) -> str:
        supplied = self.headers.get("X-Request-ID", "")
        self.request_id = supplied if REQUEST_ID.fullmatch(supplied) else uuid.uuid4().hex
        # Журнал получает локальный идентификатор, а заголовок сохраняет внешнюю корреляцию.
        self.audit_id = uuid.uuid4().hex
        return self.path.partition("?")[0]

    def _send(self, status: int, body: dict, content_type: str = "application/json") -> None:
        data = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Request-ID", self.request_id)
        self.end_headers()
        self.wfile.write(data)

    def _problem(self, status: int, title: str) -> None:
        self._send(status, {"type": "about:blank", "title": title, "status": status},
                   content_type="application/problem+json")

    def _not_found(self) -> None:
        self._problem(404, "Not Found")
        log("INFO", "http.not_found", "failure", "неизвестный адрес", request_id=self.audit_id)

    def do_GET(self) -> None:
        path = self._begin()
        if path == "/health":
            # /health не пишет в журнал: чекер ходит сюда часто и засорил бы SOC
            self._send(200, {"status": "ok"})
            return
        if path == "/api/v1/info":
            bus = self.server.bus
            try:
                blocked = bus is not None and bus.is_blocked(pseudonym("source", self.client_address[0]))
            except sqlite3.Error:
                self._problem(503, "Local Storage Unavailable")
                log("ERROR", "store.error", "failure", "локальная запись недоступна", request_id=self.audit_id)
                return
            if blocked:
                self._problem(403, "Forbidden")
                log("INFO", "authz.deny", "failure", "источник заблокирован", request_id=self.audit_id)
                return
            self._send(200, {"district": DISTRICT, "service": SERVICE})
            log("INFO", "data.read", "success", "запрошена информация о сервисе",
                actor="anonymous", request_id=self.audit_id)
            return
        self._not_found()

    def _read_block(self) -> tuple[str, str]:
        if self.headers.get_content_type() != "application/json":
            raise ValueError
        length = self.headers.get("Content-Length", "")
        if not length.isascii() or not length.isdecimal() or len(length) > 9:
            raise ValueError
        if int(length) > MAX_BODY:
            raise OverflowError
        body = json.loads(self.rfile.read(int(length)))
        if not isinstance(body, dict) or set(body) != {"source", "reason_code"}:
            raise ValueError
        source, reason = body["source"], body["reason_code"]
        if not isinstance(source, str) or "%" in source or not isinstance(reason, str) or reason not in REASONS:
            raise ValueError
        return str(ipaddress.ip_address(source)), reason

    def do_POST(self) -> None:
        if self._begin() != "/api/v1/admin/block" or self.server.bus is None:
            self._not_found()
            return
        expected = b"Bearer " + self.server.admin_token.encode()
        supplied = self.headers.get("Authorization", "").encode("latin-1")
        if not hmac.compare_digest(supplied, expected):
            self._problem(401, "Unauthorized")
            log("INFO", "authn.failure", "failure", "отклонена админ-операция", request_id=self.audit_id)
            return
        try:
            source, reason = self._read_block()
        except OverflowError:
            self._problem(413, "Content Too Large")
            return
        except (ValueError, TimeoutError):
            self._problem(400, "Invalid Block Rule")
            return
        try:
            event_id = self.server.bus.add_block(
                source, reason, request_id=self.audit_id, private_fields={"actor_id": "gateway-demo-admin"}
            )
        except BoundaryError:
            self._problem(422, "Event Blocked by Data Policy")
            log("WARN", "privacy.blocked", "failure", "событие отклонено фильтром", request_id=self.audit_id)
            return
        except sqlite3.Error:
            self._problem(503, "Local Storage Unavailable")
            log("ERROR", "store.error", "failure", "локальная запись недоступна", request_id=self.audit_id)
            return
        if event_id is None:
            self._problem(409, "Block Rule Exists")
            return
        self._send(201, {"status": "queued", "event_id": event_id})

    def log_message(self, format: str, *args: object) -> None:
        """Отключаем стандартный текстовый журнал http.server — у нас свой, в JSON."""


def _hex_secret(name: str) -> bytes:
    value = os.environ.get(name, "")
    if re.fullmatch(r"[a-fA-F0-9]{64}", value) is None:
        raise SystemExit(f"{name}: требуется 64 шестнадцатеричных символа")
    return bytes.fromhex(value)


def main() -> None:
    stop = threading.Event()
    worker = None
    with ThreadingHTTPServer((os.environ.get("BIND_HOST", "0.0.0.0"), PORT), Handler) as server:
        server.bus = None
        if broker_url := os.environ.get("BUS_URL"):
            publish_key = _hex_secret("BUS_SECRET")
            consume_key = _hex_secret("BUS_CONSUME_SECRET")
            admin_key = _hex_secret("GATEWAY_ADMIN_TOKEN")
            server.admin_token = os.environ["GATEWAY_ADMIN_TOKEN"]
            salt = get_salt()
            if len({publish_key, consume_key, salt, admin_key}) != 4:
                raise SystemExit("Ключи обмена, токен и соль должны иметь отдельные значения")
            directory = Path(os.environ.get("GATEWAY_STATE_DIR", "local/state"))
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            server.bus = GatewayBus(
                directory / "gateway.sqlite3", broker_url, publish_key, consume_key, Boundary().filter_event, log
            )
            worker = threading.Thread(target=server.bus.run, args=(stop,), daemon=True)
            worker.start()
        log("INFO", "service.start", "success", f"сервис слушает порт {PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            if worker is not None:
                worker.join(timeout=5)
            log("INFO", "service.stop", "success", "сервис остановлен")


if __name__ == "__main__":
    main()
