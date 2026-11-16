import ipaddress
import math
import ssl
from collections.abc import Callable

import dns.exception
import dns.name
import dns.reversename
import dns.resolver
import ldap3
import mysql.connector
from ldap3.core.exceptions import LDAPException

from . import remote
from .config import ConfigError, existing_file, host, port, secret, section, text, timeout
from .network import ping, tcp
from .results import Check


def guarded(target: str, label: str, action: Callable[[], Check]) -> Check:
    try:
        return action()
    except ConfigError as exc:
        return Check(target, label, "UNKNOWN", str(exc))
    except remote.RemoteError as exc:
        return Check(target, label, "CRITICAL", str(exc))


def service_check(config: dict, expected_host: str, name: str, wait: float) -> Check:
    def run() -> Check:
        windows_config = section(config, "windows")
        target = host(windows_config)
        if target.rstrip(".").lower() != expected_host.rstrip(".").lower():
            raise ConfigError(f"Le service {name} nécessite windows.host = {expected_host}")
        state = remote.windows(windows_config, wait, remote.WINDOWS_SERVICES[name])
        if state.lower() != "running":
            return Check(target, name, "CRITICAL", f"Service {name} : {state or 'état inconnu'}")
        return Check(target, name, "OK", f"Service {name} démarré")

    return guarded(expected_host, name, run)


def ldap_check(ad: dict, wait: float) -> Check:
    target = host(ad)
    ca_file = existing_file(ad, "ca_file")
    connection = None
    result = Check(target, "LDAPS", "OK", "RootDSE accessible via LDAPS avec certificat vérifié")
    try:
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file, sni=target)
        server = ldap3.Server(target, port=636, use_ssl=True, tls=tls, get_info=ldap3.NONE,
                              connect_timeout=wait)
        connection = ldap3.Connection(server, receive_timeout=math.ceil(wait), auto_referrals=False,
                                      raise_exceptions=True)
        connection.open()
        if not connection.bind():
            raise LDAPException("Échec du bind LDAP")
        if not connection.search("", "(objectClass=*)", search_scope=ldap3.BASE,
                                 attributes=["defaultNamingContext"]):
            raise LDAPException("Lecture RootDSE impossible")
        if not connection.entries:
            raise LDAPException("RootDSE vide")
    except (LDAPException, OSError, ssl.SSLError) as exc:
        result = Check(target, "LDAPS", "CRITICAL",
                       f"Connexion ou lecture LDAPS impossible ({type(exc).__name__})")
    finally:
        if connection is not None:
            try:
                connection.unbind()
            except (LDAPException, OSError) as exc:
                result = Check(target, "LDAPS", "CRITICAL",
                               f"{result.message} ; fermeture LDAPS impossible ({type(exc).__name__})")
    return result


def ad_checks(config: dict) -> list[Check]:
    try:
        wait = timeout(config)
        ad = section(config, "ad")
        target = host(ad)
    except ConfigError as exc:
        return [Check("-", "AD", "UNKNOWN", str(exc))]
    checks = [
        ping(target, wait),
        tcp(target, 389, wait, "LDAP TCP"),
        tcp(target, 636, wait, "LDAPS TCP"),
        tcp(target, 88, wait, "Kerberos TCP"),
        guarded(target, "LDAPS", lambda: ldap_check(ad, wait)),
        service_check(config, target, "NTDS", wait),
    ]
    return checks


def dns_checks(config: dict) -> list[Check]:
    try:
        wait = timeout(config)
        data = section(config, "dns")
        server = str(ipaddress.ip_address(text(data, "server")))
        expected = ipaddress.ip_address(text(data, "expected_ip"))
        name = host(data, "name")
    except (ConfigError, ValueError) as exc:
        return [Check("-", "DNS", "UNKNOWN", f"Configuration DNS invalide : {exc}")]
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.timeout = wait
    resolver.lifetime = wait
    checks = []
    try:
        answers = resolver.resolve(name, "A" if expected.version == 4 else "AAAA")
        addresses = [str(ipaddress.ip_address(answer.address)) for answer in answers]
        matched = str(expected) in addresses
        checks.append(Check(name, "DNS direct", "OK" if matched else "CRITICAL",
                            "Adresse attendue trouvée" if matched else "Adresse attendue absente",
                            {"server": server, "addresses": addresses, "expected_ip": str(expected)}))
    except (dns.exception.DNSException, OSError) as exc:
        checks.append(Check(name, "DNS direct", "CRITICAL",
                            f"Résolution directe impossible ({type(exc).__name__})", {"server": server}))
    try:
        answers = resolver.resolve(dns.reversename.from_address(str(expected)), "PTR")
        names = [str(answer.target).rstrip(".") for answer in answers]
        matched = any(candidate.lower() == name.rstrip(".").lower() for candidate in names)
        checks.append(Check(str(expected), "DNS inverse", "OK" if matched else "CRITICAL",
                            "Nom attendu trouvé" if matched else "Nom attendu absent",
                            {"server": server, "names": names, "expected_name": name}))
    except (dns.exception.DNSException, OSError) as exc:
        checks.append(Check(str(expected), "DNS inverse", "CRITICAL",
                            f"Résolution inverse impossible ({type(exc).__name__})", {"server": server}))
    try:
        service_host = host(data, "windows_host")
    except ConfigError as exc:
        checks.append(Check(server, "DNS service", "UNKNOWN", str(exc)))
    else:
        checks.append(service_check(config, service_host, "DNS", wait))
    return checks


def mysql_application(data: dict, wait: float) -> Check:
    target = host(data)
    number = port(data, 3306)
    user = text(data, "user")
    password = secret(data)
    tls = data.get("tls")
    if not isinstance(tls, bool):
        raise ConfigError("mysql.tls doit être true ou false")
    options = {
        "host": target, "port": number, "user": user, "password": password,
        "connection_timeout": max(1, int(wait)), "read_timeout": max(1, int(wait)),
        "write_timeout": max(1, int(wait)),
    }
    if tls:
        options.update(ssl_ca=existing_file(data, "ca_file"), ssl_verify_cert=True,
                       ssl_verify_identity=True)
    elif data.get("allow_insecure") is True:
        options["ssl_disabled"] = True
    else:
        raise ConfigError("MySQL sans TLS exige allow_insecure=true")
    connection = None
    cursor = None
    result = None
    try:
        connection = mysql.connector.connect(**options)
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        row = cursor.fetchone()
        if row is None or row[0] != 1:
            result = Check(target, "MySQL", "CRITICAL", "SELECT 1 a renvoyé un résultat inattendu")
        else:
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            if not version or not isinstance(version[0], str):
                result = Check(target, "MySQL", "CRITICAL", "Version MySQL indisponible")
            else:
                result = Check(target, "MySQL", "OK", "Connexion et requêtes MySQL réussies",
                               {"version": version[0], "tls": tls})
    except mysql.connector.Error as exc:
        result = Check(target, "MySQL", "CRITICAL",
                       f"Connexion ou requête MySQL impossible ({type(exc).__name__})")
    finally:
        for resource in (cursor, connection):
            if resource is not None:
                try:
                    resource.close()
                except (mysql.connector.Error, OSError) as exc:
                    previous = result.message if result is not None else "Résultat indisponible"
                    result = Check(target, "MySQL", "CRITICAL",
                                   f"{previous} ; fermeture MySQL impossible ({type(exc).__name__})")
    return result


def mysql_checks(config: dict) -> list[Check]:
    try:
        wait = timeout(config)
        data = section(config, "mysql")
        target = host(data)
        number = port(data, 3306)
    except ConfigError as exc:
        return [Check("-", "MySQL", "UNKNOWN", str(exc))]
    return [tcp(target, number, wait, "MySQL TCP"),
            guarded(target, "MySQL", lambda: mysql_application(data, wait))]


def system_check(config: dict, kind: str) -> list[Check]:
    try:
        wait = timeout(config)
        data = section(config, kind)
        target = host(data)
    except ConfigError as exc:
        return [Check("-", kind, "UNKNOWN", str(exc))]

    def run() -> Check:
        metrics = remote.windows_metrics(data, wait) if kind == "windows" else remote.linux(data, wait)
        return Check(target, kind, "OK", "Collecte système réussie", metrics)

    return [guarded(target, kind, run)]


CHECKS = {
    "ad": ad_checks,
    "dns": dns_checks,
    "mysql": mysql_checks,
    "windows": lambda config: system_check(config, "windows"),
    "linux": lambda config: system_check(config, "linux"),
}
