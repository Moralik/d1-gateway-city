"""Локальные операции с таблицей восстановления ПДн."""

import argparse
import getpass
import json
import sys

from .pseudonym import Vault


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    lookup = commands.add_parser("restore", help="показать исходное значение")
    lookup.add_argument("field")
    lookup.add_argument("token")

    deletion = commands.add_parser("delete", help="удалить соответствия по исходному значению")
    deletion.add_argument("field")

    commands.add_parser("purge", help="удалить просроченные соответствия")

    args = parser.parse_args()
    vault = Vault()
    if args.command == "purge":
        print(f"Удалено соответствий: {vault.purge()}")
        return 0
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error("Операция доступна только в локальном интерактивном терминале")
    if args.command == "delete":
        value = getpass.getpass("Исходное значение: ")
        print(f"Удалено соответствий: {vault.delete(args.field, value)}")
        return 0

    value = vault.restore(args.field, args.token)
    if value is None:
        print("Соответствие не найдено", file=sys.stderr)
        return 1
    print(json.dumps(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
