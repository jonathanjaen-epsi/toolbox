import argparse
import getpass
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .checks import CHECKS
from .config import ConfigError, load_config
from .network import ping, tcp
from .results import Check, report


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(3, f"Erreur : {message}\n")


def make_parser() -> Parser:
    parser = Parser(description="Diagnostic distant NTL-SysToolbox")
    parser.add_argument("--config", default="config.json", help="fichier JSON de configuration")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="format de sortie")
    parser.add_argument("--report", help="écrire aussi le rapport JSON à ce chemin")
    commands = parser.add_subparsers(dest="command")
    for name in ("global", "ad", "dns", "mysql", "windows", "linux"):
        commands.add_parser(name, help=f"diagnostic {name}")
    ping_parser = commands.add_parser("ping", help="test ICMP ciblé")
    ping_parser.add_argument("target")
    ping_parser.add_argument("--timeout", type=float, default=5)
    tcp_parser = commands.add_parser("tcp", help="test de port TCP ciblé")
    tcp_parser.add_argument("target")
    tcp_parser.add_argument("port", type=int)
    tcp_parser.add_argument("--timeout", type=float, default=5)
    return parser


def run(command: str, config: dict) -> list[Check]:
    if command == "global":
        return [check for name in CHECKS for check in CHECKS[name](config)]
    return CHECKS[command](config)


def mask_secrets(checks: list[Check], config: dict) -> None:
    passwords = []
    for section_name in ("windows", "mysql"):
        data = config.get(section_name)
        if isinstance(data, dict):
            name = data.get("password_env")
            value = os.environ.get(name) if isinstance(name, str) else None
            if value:
                passwords.append(value)

    def mask(value):
        if isinstance(value, str):
            for password in passwords:
                value = value.replace(password, "[masqué]")
        elif isinstance(value, list):
            value = [mask(item) for item in value]
        elif isinstance(value, dict):
            value = {key: mask(item) for key, item in value.items()}
        return value

    for check in checks:
        check.target = mask(check.target)
        check.service = mask(check.service)
        check.message = mask(check.message)
        check.details = mask(check.details)


def write_report(path: str, payload: dict) -> None:
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=destination.parent,
            prefix=f".{destination.name}.", delete=False
        ) as file:
            temporary = file.name
            json.dump(payload, file, ensure_ascii=False, indent=2)
            file.write("\n")
        os.replace(temporary, destination)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def emit(checks: list[Check], config: dict, output_format: str, destination: str | None,
         announce_report: bool = False) -> int:
    mask_secrets(checks, config)
    payload = report(checks)
    if destination:
        try:
            write_report(destination, payload)
            if announce_report:
                print(f"Rapport JSON enregistré : {destination}")
        except OSError as exc:
            checks.append(Check("-", "rapport", "UNKNOWN", f"Écriture du rapport impossible : {exc}"))
            mask_secrets(checks, config)
            payload = report(checks)
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        items = [f"{c.status} {c.service} ({c.target}): {c.message}" for c in checks]
        print(f"{payload['status']} - " + "; ".join(items).replace("\n", " ").replace("\r", " "))
    return payload["exit_code"]


def prompt_secrets(config: dict, command: str) -> None:
    required = []
    if command in ("global", "ad", "dns", "windows"):
        required.append("windows")
    if command in ("global", "mysql"):
        required.append("mysql")
    for name in required:
        data = config.get(name)
        if not isinstance(data, dict):
            continue
        variable = data.get("password_env")
        if (isinstance(variable, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable)
                and not os.environ.get(variable)):
            password = getpass.getpass(f"Mot de passe {name} ({variable}) : ")
            if password:
                os.environ[variable] = password


def menu(config_path: str, destination: str | None) -> int:
    choices = {"1": "global", "2": "ad", "3": "dns", "4": "mysql",
               "5": "windows", "6": "linux", "7": "ping", "8": "tcp"}
    while True:
        print("\nNTL-SysToolbox — diagnostics")
        print("1. Global   2. AD   3. DNS   4. MySQL/MariaDB")
        print("5. Windows  6. Linux  7. Ping  8. Port TCP  0. Quitter")
        try:
            choice = input("Choix : ").strip()
            if choice == "0":
                return 0
            command = choices.get(choice)
            if command is None:
                print("Choix invalide.")
                continue
            config = {}
            if command in ("ping", "tcp"):
                target = input("Nom d'hôte ou adresse IP : ").strip()
                if command == "tcp":
                    try:
                        number = int(input("Port TCP : ").strip())
                    except ValueError:
                        print("Port invalide.")
                        continue
                    checks = [tcp(target, number, 5)]
                else:
                    checks = [ping(target, 5)]
            else:
                try:
                    config = load_config(config_path)
                except ConfigError as exc:
                    print(f"Erreur : {exc}")
                    continue
                prompt_secrets(config, command)
                checks = run(command, config)
            report_path = destination
            if command == "global" and not report_path:
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                report_path = f"rapport-diagnostic-{stamp}.json"
            emit(checks, config, "text", report_path, announce_report=True)
            for check in checks:
                if check.details:
                    print(f"  {check.service} : {json.dumps(check.details, ensure_ascii=False)}")
        except (EOFError, KeyboardInterrupt):
            print("\nInterrompu.")
            return 3


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    if args.command is None:
        return menu(args.config, args.report)
    if args.command in ("ping", "tcp"):
        if not 0 < args.timeout <= 60:
            return emit([Check("-", args.command, "UNKNOWN", "timeout doit être compris entre 0 et 60 secondes")],
                        {}, args.format, args.report)
        check = ping(args.target, args.timeout) if args.command == "ping" else tcp(args.target, args.port, args.timeout)
        return emit([check], {}, args.format, args.report)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        return emit([Check("-", "configuration", "UNKNOWN", str(exc))], {}, args.format, args.report)
    return emit(run(args.command, config), config, args.format, args.report)


if __name__ == "__main__":
    sys.exit(main())
