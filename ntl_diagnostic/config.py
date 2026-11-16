import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


def load_config(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as file:
            data = json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Configuration illisible : {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("La configuration doit être un objet JSON")
    return data


def section(config: dict[str, Any], name: str) -> dict[str, Any]:
    value = config.get(name)
    if not isinstance(value, dict):
        raise ConfigError(f"Section {name} absente ou invalide")
    return value


def text(config: dict[str, Any], name: str) -> str:
    value = config.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"Paramètre {name} absent ou invalide")
    return value.strip()


def host(config: dict[str, Any], name: str = "host") -> str:
    value = text(config, name)
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if len(value) > 253 or not all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
        for part in value.rstrip(".").split(".")
    ):
        raise ConfigError(f"Nom d'hôte {name} invalide")
    return value


def port(config: dict[str, Any], default: int) -> int:
    value = config.get("port", default)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ConfigError("Port invalide : entier entre 1 et 65535 attendu")
    return value


def timeout(config: dict[str, Any]) -> float:
    value = config.get("timeout", 5)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 60:
        raise ConfigError("timeout doit être compris entre 0 et 60 secondes")
    return float(value)


def existing_file(config: dict[str, Any], name: str) -> str:
    path = text(config, name)
    if not Path(path).is_file():
        raise ConfigError(f"Fichier {name} introuvable ou inaccessible")
    return path


def secret(config: dict[str, Any]) -> str:
    name = text(config, "password_env")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        raise ConfigError("Nom de variable d'environnement invalide")
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"Variable d'environnement {name} absente ou vide")
    return value
