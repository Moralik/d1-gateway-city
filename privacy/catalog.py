"""Загружает разрешённые поля и их обоснования из каталога района."""

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@dataclass(frozen=True)
class FieldSpec:
    category: str
    reason: str
    allowed: frozenset[str]
    format: str | None

    def accepts_public_value(self, value: str) -> bool:
        if self.format == "uuid":
            return bool(UUID.fullmatch(value))
        return value in self.allowed


@dataclass(frozen=True)
class Catalog:
    district: str
    district_number: int
    event_types: frozenset[str]
    fields: dict[str, FieldSpec]

    @property
    def pseudonym_fields(self) -> list[str]:
        return [name for name, spec in self.fields.items() if spec.category == "pseudonym"]

    @property
    def forbidden_fields(self) -> list[str]:
        return [name for name, spec in self.fields.items() if spec.category == "forbidden"]


def load_catalog(path: str | Path | None = None) -> Catalog:
    catalog_path = Path(path or os.environ.get("PRIVACY_CATALOG", "config/privacy.toml"))
    with catalog_path.open("rb") as file:
        raw = tomllib.load(file)

    district = raw["district"]
    number = raw["district_number"]
    event_types = frozenset(raw["event_types"])
    if not re.fullmatch(r"[a-z][a-z0-9-]*", district) or type(number) is not int or number < 1:
        raise ValueError("Недействительный код района в каталоге ПДн")
    if not event_types or not all(kind.startswith(f"city.{district}.") for kind in event_types):
        raise ValueError("В каталоге ПДн должны быть исходящие типы событий своего района")

    fields = {}
    for name, spec in raw["field"].items():
        category = spec["category"]
        reason = spec["reason"]
        allowed = frozenset(spec.get("allowed", ()))
        value_format = spec.get("format")
        if category not in {"open", "pseudonym", "forbidden"} or not reason.strip():
            raise ValueError(f"Для поля {name} нужна допустимая категория и основание")
        if category == "open" and not (allowed or value_format == "uuid"):
            raise ValueError(f"Для открытого поля {name} нужен список значений или формат UUID")
        fields[name] = FieldSpec(category, reason, allowed, value_format)
    if not fields:
        raise ValueError("В каталоге ПДн нужны поля")
    return Catalog(district, number, event_types, fields)
