import math
import socket
import subprocess

from .config import ConfigError, host
from .results import Check


def ping(target: str, timeout: float) -> Check:
    try:
        host({"host": target})
        completed = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", str(math.ceil(timeout)), "--", target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
    except ConfigError as exc:
        return Check(target, "ping", "UNKNOWN", str(exc))
    except FileNotFoundError:
        return Check(target, "ping", "UNKNOWN", "Commande ping introuvable")
    except subprocess.TimeoutExpired:
        return Check(target, "ping", "CRITICAL", "Délai ICMP dépassé")
    except OSError as exc:
        return Check(target, "ping", "UNKNOWN", f"Exécution de ping impossible : {exc}")
    if completed.returncode == 0:
        return Check(target, "ping", "OK", "Réponse ICMP reçue")
    if completed.returncode == 1:
        return Check(target, "ping", "CRITICAL", "Pas de réponse ICMP : cible injoignable ou ICMP filtré")
    return Check(target, "ping", "UNKNOWN", f"Erreur de ping : {completed.stderr.strip()}")


def tcp(target: str, number: int, timeout: float, service: str | None = None) -> Check:
    label = service or f"tcp/{number}"
    try:
        host({"host": target})
        if isinstance(number, bool) or not 1 <= number <= 65535:
            raise ConfigError("Port TCP invalide")
        with socket.create_connection((target, number), timeout=timeout):
            pass
    except ConfigError as exc:
        return Check(target, label, "UNKNOWN", str(exc))
    except (OSError, TimeoutError) as exc:
        return Check(target, label, "CRITICAL", f"Connexion TCP impossible : {exc}")
    return Check(target, label, "OK", "Port TCP accessible", {"port": number})
