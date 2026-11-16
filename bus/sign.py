"""Подпись CloudEvents по учебному соглашению Р5."""

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime, timedelta
from uuid import UUID

TIME_WINDOW = timedelta(seconds=300)
UTC_MILLIS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
HEX_DIGEST = re.compile(r"[0-9a-f]{64}")


def canonical_json(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def canonical_string(event: dict) -> bytes:
    payload_hash = hashlib.sha256(canonical_json(event["data"])).hexdigest()
    return "\n".join((event["type"], event["id"], event["time"], payload_hash)).encode("utf-8")


def sign(event: dict, key: bytes) -> str:
    signature = hmac.new(key, canonical_string(event), hashlib.sha256).hexdigest()
    event["citysig"] = signature
    return signature


def verify(event: dict, key: bytes) -> bool:
    if not isinstance(event, dict):
        return False
    signature = event.get("citysig")
    if not isinstance(signature, str) or not HEX_DIGEST.fullmatch(signature):
        return False
    try:
        expected = hmac.new(key, canonical_string(event), hashlib.sha256).hexdigest()
    except (KeyError, TypeError, ValueError):
        return False
    return hmac.compare_digest(signature, expected)


def fresh(event: dict, now: datetime | None = None) -> bool:
    timestamp = event.get("time")
    if not isinstance(timestamp, str) or not UTC_MILLIS.fullmatch(timestamp):
        return False
    try:
        moment = datetime.fromisoformat(timestamp)
    except ValueError:
        return False
    return abs((now or datetime.now(UTC)) - moment) <= TIME_WINDOW


def is_uuid(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False
