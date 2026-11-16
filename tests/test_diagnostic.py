import contextlib
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import dns.exception
import mysql.connector
import paramiko
import requests
from ldap3.core import tls as ldap_tls
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ntl_diagnostic import checks, cli, remote
from ntl_diagnostic.config import ConfigError
from ntl_diagnostic.network import ping, tcp
from ntl_diagnostic.results import Check, report


class ResultTests(unittest.TestCase):
    def test_priority_and_codes(self):
        unknown = Check("a", "test", "UNKNOWN", "absent")
        warning = Check("b", "test", "WARNING", "attention")
        critical = Check("c", "test", "CRITICAL", "connexion impossible")
        self.assertEqual(report([warning, unknown])["status"], "UNKNOWN")
        result = report([unknown, critical])
        self.assertEqual((result["status"], result["exit_code"]), ("CRITICAL", 2))
        self.assertEqual(len(result["checks"]), 2)

    def test_report_and_redaction(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"TEST_PASSWORD": "secret-value"}):
            output = io.StringIO()
            check = Check("server", "test", "CRITICAL", "secret-value", {"error": "secret-value"})
            path = str(Path(directory) / "report.json")
            with contextlib.redirect_stdout(output):
                code = cli.emit([check], {"mysql": {"password_env": "TEST_PASSWORD"}}, "json", path)
            self.assertEqual(code, 2)
            self.assertNotIn("secret-value", output.getvalue())
            self.assertNotIn("secret-value", Path(path).read_text())
            self.assertEqual(json.loads(Path(path).read_text())["status"], "CRITICAL")

    def test_report_write_error_is_visible(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.emit([Check("a", "test", "OK", "ok")], {}, "json", "/no-such-directory/report.json")
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["checks"][-1]["service"], "rapport")


class NetworkTests(unittest.TestCase):
    def test_open_and_closed_tcp(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            number = listener.getsockname()[1]
            self.assertEqual(tcp("127.0.0.1", number, 1).status, "OK")
        self.assertEqual(tcp("127.0.0.1", number, 1).status, "CRITICAL")

    def test_rejects_option_injection(self):
        with patch("ntl_diagnostic.network.subprocess.run") as subprocess_run:
            self.assertEqual(ping("-bad-option", 1).status, "UNKNOWN")
            subprocess_run.assert_not_called()

    def test_ping_blocked_is_explicit(self):
        with patch("ntl_diagnostic.network.subprocess.run", return_value=SimpleNamespace(returncode=1, stderr="")):
            result = ping("server.example", 1)
        self.assertEqual(result.status, "CRITICAL")
        self.assertIn("ICMP filtré", result.message)


class ADTests(unittest.TestCase):
    def test_ldaps_rejects_certificate_for_another_host(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wrong.example")])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(minutes=1))
                       .not_valid_after(now + timedelta(days=1))
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName("wrong.example")]), False)
                       .sign(key, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as directory:
            cert_file, key_file = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                                    serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_file, key_file)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(3)
                number = listener.getsockname()[1]

                def serve():
                    try:
                        conn, _ = listener.accept()
                        with conn, context.wrap_socket(conn, server_side=True):
                            pass
                    except (OSError, ssl.SSLError):
                        pass

                thread = threading.Thread(target=serve)
                thread.start()
                original_server = checks.ldap3.Server

                def local_server(*args, **kwargs):
                    kwargs["port"] = number
                    return original_server(*args, **kwargs)

                try:
                    with warnings.catch_warnings(), \
                         patch("ntl_diagnostic.checks.ldap3.Server", side_effect=local_server), \
                         patch("ldap3.core.tls.check_hostname", wraps=ldap_tls.check_hostname) as hostname_check:
                        warnings.filterwarnings("ignore", category=ResourceWarning, module="ldap3.strategy.base")
                        result = checks.ldap_check({"host": "127.0.0.1", "ca_file": str(cert_file)}, 2)
                finally:
                    thread.join(timeout=4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result.status, "CRITICAL")
        hostname_check.assert_called_once()

    @patch("ntl_diagnostic.checks.ldap3.Connection")
    @patch("ntl_diagnostic.checks.ldap3.Server")
    @patch("ntl_diagnostic.checks.ldap3.Tls")
    def test_ldaps_validates_certificate_and_queries_rootdse(self, tls, server, connection):
        conn = connection.return_value
        conn.bind.return_value = True
        conn.search.return_value = True
        conn.entries = [object()]
        with tempfile.NamedTemporaryFile() as ca:
            result = checks.ldap_check({"host": "dc.example", "ca_file": ca.name}, 2.5)
        self.assertEqual(result.status, "OK")
        self.assertEqual(tls.call_args.kwargs["validate"], ssl.CERT_REQUIRED)
        self.assertEqual(tls.call_args.kwargs["sni"], "dc.example")
        self.assertTrue(server.call_args.kwargs["use_ssl"])
        self.assertEqual(connection.call_args.kwargs["receive_timeout"], 3)
        conn.search.assert_called_once()
        conn.unbind.assert_called_once()

    def test_ad_service_cannot_use_another_server(self):
        result = checks.service_check({"windows": {"host": "other.example"}}, "dc.example", "NTDS", 1)
        self.assertEqual(result.status, "UNKNOWN")


class DNSTests(unittest.TestCase):
    def test_direct_and_reverse_and_service(self):
        config = {"dns": {"server": "192.0.2.1", "name": "dc.example", "expected_ip": "192.0.2.5",
                          "windows_host": "dc.example"}}
        resolver = MagicMock()
        resolver.resolve.side_effect = [
            [SimpleNamespace(address="192.0.2.5")],
            [SimpleNamespace(target="dc.example.")],
        ]
        with patch("ntl_diagnostic.checks.dns.resolver.Resolver", return_value=resolver), \
             patch("ntl_diagnostic.checks.service_check", return_value=Check("dc.example", "DNS", "OK", "ok")):
            result = checks.dns_checks(config)
        self.assertEqual([item.status for item in result], ["OK", "OK", "OK"])
        self.assertEqual(resolver.nameservers, ["192.0.2.1"])

    def test_dns_timeout_and_inconsistent_ptr(self):
        config = {"dns": {"server": "192.0.2.1", "name": "dc.example", "expected_ip": "192.0.2.5"}}
        resolver = MagicMock()
        resolver.resolve.side_effect = [dns.exception.Timeout(), [SimpleNamespace(target="other.example.")]]
        with patch("ntl_diagnostic.checks.dns.resolver.Resolver", return_value=resolver):
            result = checks.dns_checks(config)
        self.assertEqual([item.status for item in result], ["CRITICAL", "CRITICAL", "UNKNOWN"])


class MySQLTests(unittest.TestCase):
    def test_secure_mysql_and_queries(self):
        connection = MagicMock()
        cursor = connection.cursor.return_value
        cursor.fetchone.side_effect = [(1,), ("MariaDB",)]
        with tempfile.NamedTemporaryFile() as ca, patch.dict(os.environ, {"DB_PASSWORD": "password"}), \
             patch("ntl_diagnostic.checks.mysql.connector.connect", return_value=connection) as connect:
            result = checks.mysql_application({"host": "db.example", "user": "monitor", "password_env": "DB_PASSWORD",
                                               "tls": True, "ca_file": ca.name}, 2)
        self.assertEqual(result.status, "OK")
        self.assertEqual(result.details["version"], "MariaDB")
        self.assertTrue(connect.call_args.kwargs["ssl_verify_identity"])
        self.assertTrue(connect.call_args.kwargs["ssl_verify_cert"])
        self.assertEqual(cursor.execute.call_count, 2)
        connection.close.assert_called_once()

    def test_insecure_mysql_requires_explicit_permission(self):
        data = {"host": "db.example", "user": "monitor", "password_env": "DB_PASSWORD", "tls": False}
        with patch.dict(os.environ, {"DB_PASSWORD": "password"}):
            with self.assertRaises(ConfigError):
                checks.mysql_application(data, 2)
            connection = MagicMock()
            connection.cursor.return_value.fetchone.side_effect = [(1,), ("MariaDB",)]
            with patch("ntl_diagnostic.checks.mysql.connector.connect", return_value=connection) as connect:
                self.assertEqual(checks.mysql_application({**data, "allow_insecure": True}, 2).status, "OK")
            self.assertTrue(connect.call_args.kwargs["ssl_disabled"])

    def test_mysql_failure_does_not_expose_exception(self):
        data = {"host": "db.example", "user": "monitor", "password_env": "DB_PASSWORD",
                "tls": False, "allow_insecure": True}
        with patch.dict(os.environ, {"DB_PASSWORD": "password"}), \
             patch("ntl_diagnostic.checks.mysql.connector.connect",
                   side_effect=mysql.connector.Error("password")):
            result = checks.mysql_application(data, 1)
        self.assertEqual(result.status, "CRITICAL")
        self.assertNotIn("password", result.message)


class RemoteTests(unittest.TestCase):
    def test_linux_collector_runs_and_produces_valid_metrics(self):
        output = subprocess.run(
            [sys.executable, "-c", remote.LINUX_SCRIPT], capture_output=True, text=True,
            check=True, timeout=5,
        )
        metrics = remote.validate_metrics(json.loads(output.stdout), "linux")
        self.assertGreater(metrics["memory_total_bytes"], 0)

    def test_winrm_uses_https_and_verified_ca(self):
        response = SimpleNamespace(status_code=0, std_out=b"Running")
        with tempfile.NamedTemporaryFile() as ca, patch.dict(os.environ, {"WIN_PASSWORD": "password"}), \
             patch("ntl_diagnostic.remote.winrm.Session") as session:
            session.return_value.run_ps.return_value = response
            config = {"host": "dc.example", "user": "user", "password_env": "WIN_PASSWORD", "ca_file": ca.name}
            self.assertEqual(remote.windows(config, 2, remote.WINDOWS_SERVICES["NTDS"]), "Running")
            args, kwargs = session.call_args
            self.assertTrue(args[0].startswith("https://"))
            self.assertEqual(kwargs["server_cert_validation"], "validate")
            self.assertEqual(kwargs["ca_trust_path"], ca.name)

    def test_winrm_failure_is_reported_without_secret(self):
        with tempfile.NamedTemporaryFile() as ca, patch.dict(os.environ, {"WIN_PASSWORD": "password"}), \
             patch("ntl_diagnostic.remote.winrm.Session", side_effect=requests.exceptions.SSLError("password")):
            config = {"host": "dc.example", "user": "user", "password_env": "WIN_PASSWORD", "ca_file": ca.name}
            with self.assertRaises(remote.RemoteError) as error:
                remote.windows(config, 2, remote.WINDOWS_SERVICES["NTDS"])
            self.assertNotIn("password", str(error.exception))

    def test_ssh_requires_known_host_and_key(self):
        client = MagicMock()
        stdout, stderr = MagicMock(), MagicMock()
        stdout.read.return_value = json.dumps({
            "distribution": "Debian", "uptime_seconds": 100, "cpu_percent": 5,
            "memory_total_bytes": 100, "memory_available_bytes": 20,
            "disk_path": "/", "disk_total_bytes": 1000, "disk_free_bytes": 500,
        }).encode()
        stdout.channel.recv_exit_status.return_value = 0
        stderr.read.return_value = b""
        client.exec_command.return_value = (None, stdout, stderr)
        with tempfile.NamedTemporaryFile() as key, tempfile.NamedTemporaryFile() as hosts, \
             patch("ntl_diagnostic.remote.paramiko.SSHClient", return_value=client):
            data = remote.linux({"host": "linux.example", "user": "monitor", "key_file": key.name,
                                 "known_hosts": hosts.name}, 2)
        self.assertEqual(data["cpu_percent"], 5)
        self.assertIsInstance(client.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)
        self.assertFalse(client.connect.call_args.kwargs["allow_agent"])
        self.assertFalse(client.connect.call_args.kwargs["look_for_keys"])
        client.close.assert_called_once()

    def test_incomplete_metrics_cannot_report_success(self):
        with self.assertRaises(remote.RemoteError):
            remote.validate_metrics({"cpu_percent": 5}, "linux")

    def test_mysql_cleanup_failure_is_reported(self):
        data = {"host": "db.example", "user": "monitor", "password_env": "DB_PASSWORD",
                "tls": False, "allow_insecure": True}
        connection = MagicMock()
        connection.cursor.return_value.fetchone.side_effect = [(1,), ("MariaDB",)]
        connection.close.side_effect = mysql.connector.Error("connection lost")
        with patch.dict(os.environ, {"DB_PASSWORD": "password"}), \
             patch("ntl_diagnostic.checks.mysql.connector.connect", return_value=connection):
            result = checks.mysql_application(data, 1)
        self.assertEqual(result.status, "CRITICAL")
        self.assertIn("fermeture", result.message)


class CLITests(unittest.TestCase):
    def test_global_json_is_written_and_contains_every_missing_service(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            destination = Path(directory) / "report.json"
            config.write_text("{}", encoding="utf-8")
            with contextlib.redirect_stdout(output):
                code = cli.main(["--config", str(config), "--format", "json",
                                 "--report", str(destination), "global"])
            payload = json.loads(output.getvalue())
            self.assertEqual(payload, json.loads(destination.read_text(encoding="utf-8")))
        self.assertEqual(code, 3)
        self.assertEqual([item["service"] for item in payload["checks"]],
                         ["AD", "DNS", "MySQL", "windows", "linux"])

    def test_menu_global_saves_a_json_report(self):
        output = io.StringIO()
        with patch("builtins.input", side_effect=["1", "0"]), \
             patch("ntl_diagnostic.cli.load_config", return_value={}), \
             patch("ntl_diagnostic.cli.write_report") as write, \
             contextlib.redirect_stdout(output):
            self.assertEqual(cli.menu("config.json", None), 0)
        path, payload = write.call_args.args
        self.assertRegex(path, r"^rapport-diagnostic-\d{8}T\d{12}Z\.json$")
        self.assertEqual(payload["status"], "UNKNOWN")
        self.assertIn("Rapport JSON enregistré", output.getvalue())

    def test_global_continues_when_sections_missing(self):
        result = cli.run("global", {})
        self.assertEqual(len(result), 5)
        self.assertTrue(all(item.status == "UNKNOWN" for item in result))

    def test_global_continues_after_critical(self):
        funcs = {
            "ad": lambda _: [Check("dc", "AD", "CRITICAL", "connexion impossible")],
            "linux": lambda _: [Check("linux", "Linux", "OK", "ok")],
        }
        with patch.dict(checks.CHECKS, funcs, clear=True):
            result = cli.run("global", {})
        self.assertEqual([check.status for check in result], ["CRITICAL", "OK"])

    def test_invalid_config_and_cli_timeout_return_unknown_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(["--format", "json", "--config", "/does-not-exist", "global"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["status"], "UNKNOWN")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = cli.main(["--format", "json", "ping", "127.0.0.1", "--timeout", "0"])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(output.getvalue())["status"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
