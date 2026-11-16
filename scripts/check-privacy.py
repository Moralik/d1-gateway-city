#!/usr/bin/env python3
"""Девять проверок ЛР5 на синтетических данных и во временных хранилищах."""

import json
import re
import subprocess
import sys
from pathlib import Path
from secrets import token_bytes, token_hex
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bus.producer import GATEWAY_SOURCE, OUTGOING_TYPE, GatewayBus, build_event
from bus.sign import verify
from bus.store import connect
from privacy import Boundary, BoundaryError, restore
from privacy.pseudonym import SALT_ENV, get_salt, pseudonym

SOURCE = "192.0.2.42"
ACTOR = "synthetic-gateway-operator"
PSEUDONYM = re.compile(r"psn:[0-9a-f]{32}")


def require(condition, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def block_event(**data) -> dict:
    block_id = str(uuid4())
    payload = {"block_id": block_id, "source": SOURCE, "reason_code": "scan", "actor_id": ACTOR, **data}
    return build_event(OUTGOING_TYPE, payload, GATEWAY_SOURCE, block_id)


def probe_bus(path: Path, boundary: Boundary, key: bytes) -> GatewayBus:
    # Проверки читают транзакции очереди напрямую. Брокер и сеть здесь не используются.
    return GatewayBus(
        path, "http://127.0.0.1:1", key, token_bytes(32), boundary.filter_event, lambda *args, **fields: None
    )


def check_categories(boundary: Boundary) -> None:
    raw = block_event()
    filtered = boundary.filter_event(raw)
    for field in ("source", "actor_id"):
        require(PSEUDONYM.fullmatch(filtered["data"][field]), f"Поле {field} не псевдонимизировано")
    for field in ("block_id", "reason_code"):
        require(filtered["data"][field] == raw["data"][field], f"Открытое поле {field} изменилось")
    require(raw["data"]["source"] == SOURCE, "Фильтр мутировал входное событие")


def check_stability(boundary: Boundary) -> None:
    first = boundary.filter_event(block_event())
    second = boundary.filter_event(block_event())
    require(first["data"]["actor_id"] == second["data"]["actor_id"], "Псевдоним меняется от события к событию")


def check_context(boundary: Boundary) -> None:
    data = boundary.filter_event(block_event(actor_id=SOURCE))["data"]
    require(data["source"] != data["actor_id"], "Одно значение в разных полях дало одинаковые псевдонимы")


def check_salt(boundary: Boundary) -> None:
    ours = boundary.filter_event(block_event())["data"]["source"]
    try:
        with patch.dict("os.environ", {SALT_ENV: token_hex(32)}):
            get_salt.cache_clear()
            theirs = pseudonym("source", SOURCE)
    finally:
        get_salt.cache_clear()
    require(ours != theirs, "Другая соль дала тот же псевдоним")


def check_signed_queue(temp: Path, boundary: Boundary) -> None:
    key = token_bytes(32)
    bus = probe_bus(temp / "signed.sqlite3", boundary, key)
    event_id = bus.add_block(SOURCE, "scan", private_fields={"actor_id": ACTOR})
    with connect(bus.db_path) as db:
        row = db.execute("SELECT event FROM outbox WHERE event_id = ?", (event_id,)).fetchone()
    require(row is not None, "Событие отсутствует в очереди")
    serialized = row[0]
    require(SOURCE not in serialized and ACTOR not in serialized, "Исходные ПДн обнаружены в очереди")
    event = json.loads(serialized)
    require(verify(event, key), "Подпись отфильтрованного события не проходит проверку")
    event["data"]["source"] = "psn:" + token_hex(16)
    require(not verify(event, key), "Подменённые данные сохранили валидную подпись")


def check_blocked(temp: Path) -> None:
    boundary = Boundary(ROOT / "config/privacy.toml", temp / "rejected-vault.sqlite3")
    bus = probe_bus(temp / "rejected-queue.sqlite3", boundary, token_bytes(32))
    for field, expected in (("debug_context", "forbidden_field"), ("debug_extra", "unknown_field")):
        try:
            bus.add_block(SOURCE, "scan", private_fields={"actor_id": ACTOR, field: "synthetic-secret"})
        except BoundaryError as error:
            require(error.code == expected, "Фильтр вернул неверную причину отказа")
        else:
            raise AssertionError("Опасное поле прошло границу")
    with connect(bus.db_path) as db:
        require(db.execute("SELECT 1 FROM outbox").fetchone() is None, "Отклонённое событие записано в очередь")
        require(db.execute("SELECT 1 FROM blocks").fetchone() is None, "Отклонённое правило сохранено")
    require(not boundary.vault.path.exists(), "Отклонённое событие изменило таблицу восстановления")


def check_git() -> None:
    if not (ROOT / ".git").exists():
        patterns = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        require(".env" in patterns and "/local/" in patterns, "Для архива нужны правила защиты .env и local/")
        return
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    for path in result.stdout.decode("utf-8").split("\0"):
        local = path.startswith("local/") or "/private/" in path or path.endswith("vault.sqlite3")
        filename = Path(path).name
        env = filename == ".env" or filename.startswith(".env.") and filename != ".env.example"
        require(not local and not env, "Git отслеживает файл с локальными данными или секретами")
    for path in (".env", "local/vault.sqlite3"):
        result = subprocess.run(["git", "check-ignore", "--no-index", "--quiet", path], cwd=ROOT)
        require(result.returncode == 0, f"Git не исключает {path}")


def check_restore(boundary: Boundary) -> None:
    alias = boundary.filter_event(block_event())["data"]["source"]
    require(restore("source", alias) == SOURCE, "Локальное восстановление вернуло неверное значение")
    require(boundary.vault.delete("source", SOURCE) == 1, "Значение не удалилось из таблицы")
    require(restore("source", alias) is None, "Значение всё ещё доступно после удаления")


def check_recovery() -> None:
    recovery = (ROOT / "docs/recovery.md").read_text(encoding="utf-8").lower()
    require(re.search(r"^## .*пдн", recovery, re.MULTILINE), "В recovery.md нужен раздел ПДн")
    for term in ("срок", "vault", "удал"):
        require(term in recovery, "Нужны срок, место хранения и порядок удаления ПДн")


def main() -> int:
    with TemporaryDirectory() as directory:
        temp = Path(directory)
        vault = temp / "vault.sqlite3"
        with patch.dict("os.environ", {SALT_ENV: token_hex(32), "PRIVACY_VAULT": str(vault)}):
            get_salt.cache_clear()
            boundary = Boundary(ROOT / "config/privacy.toml", vault)
            checks = [
                ("Псевдонимы и открытые поля", lambda: check_categories(boundary)),
                ("Стабильность псевдонима", lambda: check_stability(boundary)),
                ("Контекст поля", lambda: check_context(boundary)),
                ("Разные соли районов", lambda: check_salt(boundary)),
                ("Подпись после фильтра и отсутствие ПДн в очереди", lambda: check_signed_queue(temp, boundary)),
                ("Запрет известных и неизвестных полей", lambda: check_blocked(temp)),
                ("Соль и локальная таблица исключены из Git", check_git),
                ("Локальное восстановление и удаление", lambda: check_restore(boundary)),
                ("Раздел ПДн в инструкции восстановления", check_recovery),
            ]
            passed = 0
            for index, (title, check) in enumerate(checks, 1):
                try:
                    check()
                except Exception as error:
                    print(f"[FAIL] {index}. {title} — {error}")
                else:
                    passed += 1
                    print(f"[OK]   {index}. {title}")
    print(f"\nПройдено {passed} из {len(checks)}")
    return int(passed != len(checks))


if __name__ == "__main__":
    raise SystemExit(main())
