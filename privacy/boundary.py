"""Применяет каталог ПДн перед подписью исходящего события."""

import re
from datetime import datetime
from pathlib import Path

from .catalog import UUID, load_catalog
from .pseudonym import Vault, pseudonym

PUBLIC_ATTRIBUTES = {"specversion", "id", "source", "type", "time", "subject", "datacontenttype", "data"}
UTC_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?Z")
BLOCK_FIELDS = {"block_id", "source", "reason_code"}


class BoundaryError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _valid_time(value: str) -> bool:
    if not UTC_STAMP.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


class Boundary:
    def __init__(self, catalog_path: str | Path | None = None, vault_path: str | Path | None = None) -> None:
        self.catalog = load_catalog(catalog_path)
        self.vault = Vault(vault_path)

    def _validate_envelope(self, event: dict) -> bool:
        if not isinstance(event, dict) or event.keys() - PUBLIC_ATTRIBUTES:
            raise BoundaryError("invalid_envelope")
        required = {"id", "source", "type", "time", "data"}
        if not required <= event.keys() or not isinstance(event["data"], dict):
            raise BoundaryError("invalid_envelope")
        if any(not isinstance(event[name], str) for name in event.keys() - {"data"}):
            raise BoundaryError("invalid_envelope")

        district = self.catalog.district
        source = f"/d{self.catalog.district_number}-{district}/api"
        is_block = event["type"] == f"city.{district}.block.added.v1"
        sources = {source} if is_block else {source, f"/d-{district}/api"}
        if (event["type"] not in self.catalog.event_types or event["source"] not in sources
                or not UUID.fullmatch(event["id"]) or not _valid_time(event["time"])
                or event.get("specversion", "1.0") != "1.0"
                or event.get("datacontenttype", "application/json") != "application/json"):
            raise BoundaryError("invalid_envelope")
        if is_block and (event.keys() != PUBLIC_ATTRIBUTES or "." not in event["time"]):
            raise BoundaryError("invalid_envelope")
        if "subject" in event:
            subject = event["subject"]
            if not UUID.fullmatch(subject) or event["data"].get("block_id") != subject:
                raise BoundaryError("invalid_envelope")
        return is_block

    def filter_event(self, event: dict) -> dict:
        is_block = self._validate_envelope(event)
        public_data = {}
        mappings = []
        for name, value in event["data"].items():
            spec = self.catalog.fields.get(name)
            if spec is None:
                raise BoundaryError("unknown_field")
            if spec.category == "forbidden":
                raise BoundaryError("forbidden_field")
            if not isinstance(value, str) or not 1 <= len(value) <= 256:
                raise BoundaryError("invalid_value")
            if spec.category == "open":
                if not spec.accepts_public_value(value):
                    raise BoundaryError("invalid_value")
                public_data[name] = value
                continue

            try:
                token = pseudonym(name, value)
            except UnicodeEncodeError:
                raise BoundaryError("invalid_value") from None
            mappings.append((name, token, value))
            public_data[name] = token

        if is_block and not BLOCK_FIELDS <= public_data.keys() <= BLOCK_FIELDS | {"actor_id"}:
            raise BoundaryError("invalid_data_shape")
        self.vault.remember(mappings)
        return {**event, "data": public_data}


def filter_event(event: dict) -> dict:
    return Boundary().filter_event(event)


def try_filter_event(event: dict) -> tuple[bool, dict | None, str]:
    try:
        return True, filter_event(event), ""
    except BoundaryError as error:
        return False, None, f"blocked: {error.code}"
