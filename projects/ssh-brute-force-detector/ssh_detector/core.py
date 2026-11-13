"""Parse SSH syslog failures and find bursts of failed password attempts."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

FAILED_PASSWORD = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]: "
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\S+) port \d+\b"
)


@dataclass(frozen=True)
class Attempt:
    ip: str
    occurred_at: datetime


@dataclass(frozen=True)
class Finding:
    ip: str
    attempts: int
    first_seen: str
    last_seen: str


def parse_attempt(line: str, year: int) -> Attempt | None:
    """Return a failed password event from a syslog line, if supported."""
    match = FAILED_PASSWORD.search(line)
    if match is None:
        return None

    try:
        address = str(ipaddress.ip_address(match.group("ip")))
        moment = datetime.strptime(
            f'{year} {match.group("month")} {match.group("day")} {match.group("time")}',
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None

    return Attempt(ip=address, occurred_at=moment)


def analyze_lines(
    lines: Iterable[str],
    *,
    threshold: int = 5,
    window_minutes: int = 10,
    year: int,
) -> list[Finding]:
    """Report the densest failed-login window for each suspicious source IP."""
    if threshold < 1 or window_minutes < 1:
        raise ValueError("threshold and window_minutes must be positive")

    attempts = (parse_attempt(line, year) for line in lines)
    ordered = sorted(
        (attempt for attempt in attempts if attempt is not None),
        key=lambda attempt: attempt.occurred_at,
    )
    windows: dict[str, deque[datetime]] = defaultdict(deque)
    findings: dict[str, Finding] = {}
    duration = timedelta(minutes=window_minutes)

    for attempt in ordered:
        window = windows[attempt.ip]
        while window and attempt.occurred_at - window[0] > duration:
            window.popleft()
        window.append(attempt.occurred_at)

        if len(window) >= threshold:
            previous = findings.get(attempt.ip)
            if previous is None or len(window) > previous.attempts:
                findings[attempt.ip] = Finding(
                    ip=attempt.ip,
                    attempts=len(window),
                    first_seen=window[0].isoformat(timespec="seconds"),
                    last_seen=window[-1].isoformat(timespec="seconds"),
                )

    return sorted(findings.values(), key=lambda item: (-item.attempts, item.ip))
