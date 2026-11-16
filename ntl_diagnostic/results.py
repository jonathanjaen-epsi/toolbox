from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


CODES = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}
PRIORITY = {"OK": 0, "WARNING": 1, "UNKNOWN": 2, "CRITICAL": 3}


@dataclass
class Check:
    target: str
    service: str
    status: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def report(checks: list[Check]) -> dict[str, Any]:
    if not checks:
        checks = [Check("-", "diagnostic", "UNKNOWN", "Aucun contrôle effectué")]
    status = max((check.status for check in checks), key=PRIORITY.__getitem__)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "exit_code": CODES[status],
        "checks": [asdict(check) for check in checks],
    }
