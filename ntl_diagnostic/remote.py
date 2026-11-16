import json
import math
import shlex
import socket

import paramiko
import requests
import winrm
from spnego.exceptions import SpnegoError
from winrm.exceptions import WinRMError

from .config import ConfigError, existing_file, host, port, secret, text


class RemoteError(Exception):
    pass


def validate_metrics(data: dict, kind: str) -> dict:
    def number(key: str, maximum: float | None = None) -> float:
        value = data.get(key)
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value < 0
                or (maximum is not None and value > maximum)):
            raise RemoteError(f"Métrique {kind} invalide : {key}")
        return value

    identity = "distribution" if kind == "linux" else "version"
    if not isinstance(data.get(identity), str) or not data[identity].strip():
        raise RemoteError(f"Métrique {kind} invalide : {identity}")
    number("uptime_seconds")
    number("cpu_percent", 100)
    total = number("memory_total_bytes")
    if total == 0 or number("memory_available_bytes") > total:
        raise RemoteError(f"Métrique {kind} invalide : mémoire")
    if kind == "linux":
        disk_total = number("disk_total_bytes")
        if (not isinstance(data.get("disk_path"), str) or not data["disk_path"]
                or disk_total == 0 or number("disk_free_bytes") > disk_total):
            raise RemoteError("Métrique linux invalide : disque")
    else:
        disks = data.get("disks")
        if not isinstance(disks, list) or not disks:
            raise RemoteError("Métrique windows invalide : disques")
        for disk in disks:
            if not isinstance(disk, dict) or not isinstance(disk.get("path"), str) or not disk["path"]:
                raise RemoteError("Métrique windows invalide : disque")
            disk_total, disk_free = disk.get("total_bytes"), disk.get("free_bytes")
            if (isinstance(disk_total, bool) or isinstance(disk_free, bool)
                    or not isinstance(disk_total, (int, float))
                    or not isinstance(disk_free, (int, float))
                    or not math.isfinite(disk_total) or not math.isfinite(disk_free)
                    or disk_total <= 0 or not 0 <= disk_free <= disk_total):
                raise RemoteError("Métrique windows invalide : capacité disque")
    return data


LINUX_SCRIPT = r"""
import json, os, shutil, time
def cpu():
    with open('/proc/stat', encoding='utf-8') as f:
        values = [int(x) for x in f.readline().split()[1:]]
    return sum(values), values[3] + values[4]
total1, idle1 = cpu()
time.sleep(1)
total2, idle2 = cpu()
with open('/proc/meminfo', encoding='utf-8') as f:
    memory = {line.split(':', 1)[0]: int(line.split(':', 1)[1].split()[0]) * 1024
              for line in f if line.startswith(('MemTotal:', 'MemAvailable:'))}
with open('/proc/uptime', encoding='utf-8') as f:
    uptime = float(f.read().split()[0])
with open('/etc/os-release', encoding='utf-8') as f:
    release = dict(line.rstrip().split('=', 1) for line in f if '=' in line)
disk = shutil.disk_usage('/')
print(json.dumps({
    'distribution': release.get('PRETTY_NAME', '').strip('"'),
    'uptime_seconds': uptime,
    'cpu_percent': round(100 * (1 - (idle2 - idle1) / (total2 - total1)), 2),
    'memory_total_bytes': memory['MemTotal'],
    'memory_available_bytes': memory['MemAvailable'],
    'disk_path': '/',
    'disk_total_bytes': disk.total,
    'disk_free_bytes': disk.free
}))
"""

WINDOWS_METRICS = r"""
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem
$cpu = @(Get-CimInstance Win32_Processor)
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  @{ path = $_.DeviceID; total_bytes = $_.Size; free_bytes = $_.FreeSpace }
})
$data = @{
  version = $os.Caption
  uptime_seconds = [int64]((Get-Date) - $os.LastBootUpTime).TotalSeconds
  cpu_percent = [double](($cpu | Measure-Object -Property LoadPercentage -Average).Average)
  memory_total_bytes = [int64]$os.TotalVisibleMemorySize * 1024
  memory_available_bytes = [int64]$os.FreePhysicalMemory * 1024
  disks = $disks
}
$data | ConvertTo-Json -Depth 4 -Compress
"""

WINDOWS_SERVICES = {
    "NTDS": "$ErrorActionPreference='Stop'; (Get-Service -Name 'NTDS').Status.ToString()",
    "DNS": "$ErrorActionPreference='Stop'; (Get-Service -Name 'DNS').Status.ToString()",
}


def windows(config: dict, timeout: float, script: str) -> str:
    target = host(config)
    number = port(config, 5986)
    user = text(config, "user")
    password = secret(config)
    ca_file = existing_file(config, "ca_file")
    transport = config.get("transport", "ntlm")
    if transport not in ("ntlm", "basic"):
        raise ConfigError("Transport WinRM attendu : ntlm ou basic")
    endpoint_host = f"[{target}]" if ":" in target else target
    try:
        session = winrm.Session(
            f"https://{endpoint_host}:{number}/wsman",
            auth=(user, password),
            transport=transport,
            server_cert_validation="validate",
            ca_trust_path=ca_file,
            operation_timeout_sec=max(1, int(timeout)),
            read_timeout_sec=max(2, int(timeout) + 2),
        )
        response = session.run_ps(script)
    except (requests.RequestException, WinRMError, SpnegoError, OSError, ValueError) as exc:
        raise RemoteError(f"Connexion WinRM impossible ({type(exc).__name__})") from exc
    if response.status_code != 0:
        raise RemoteError(f"Commande PowerShell échouée (code {response.status_code})")
    try:
        return response.std_out.decode("utf-8-sig").strip()
    except UnicodeError as exc:
        raise RemoteError("Réponse PowerShell illisible") from exc


def linux(config: dict, timeout: float) -> dict:
    target = host(config)
    number = port(config, 22)
    user = text(config, "user")
    key_file = existing_file(config, "key_file")
    known_hosts = existing_file(config, "known_hosts")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.load_host_keys(known_hosts)
        client.connect(
            target, port=number, username=user, key_filename=key_file,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            allow_agent=False, look_for_keys=False,
        )
        _, stdout, stderr = client.exec_command(
            "python3 -c " + shlex.quote(LINUX_SCRIPT), timeout=timeout + 2
        )
        output = stdout.read(1024 * 1024 + 1)
        error = stderr.read(1024 * 1024 + 1)
        status = stdout.channel.recv_exit_status()
    except (OSError, EOFError, paramiko.SSHException, socket.timeout) as exc:
        raise RemoteError(f"Connexion ou collecte SSH impossible ({type(exc).__name__})") from exc
    finally:
        client.close()
    if status != 0:
        raise RemoteError(f"Collecte Linux échouée (code {status})")
    if len(output) > 1024 * 1024 or len(error) > 1024 * 1024:
        raise RemoteError("Réponse SSH trop volumineuse")
    try:
        data = json.loads(output)
    except (ValueError, UnicodeError) as exc:
        raise RemoteError("Réponse Linux JSON invalide") from exc
    if not isinstance(data, dict):
        raise RemoteError("Réponse Linux JSON inattendue")
    return validate_metrics(data, "linux")


def windows_metrics(config: dict, timeout: float) -> dict:
    try:
        data = json.loads(windows(config, timeout, WINDOWS_METRICS))
    except ValueError as exc:
        raise RemoteError("Réponse Windows JSON invalide") from exc
    if not isinstance(data, dict):
        raise RemoteError("Réponse Windows JSON inattendue")
    return validate_metrics(data, "windows")
