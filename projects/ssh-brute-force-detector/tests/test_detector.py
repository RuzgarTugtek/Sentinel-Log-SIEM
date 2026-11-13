"""Regression tests for SSH log parsing and sliding-window detection."""

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from ssh_detector.__main__ import main
from ssh_detector.core import analyze_lines, parse_attempt


def log_line(time: str, ip: str = "198.51.100.23") -> str:
    return (
        f"Nov 14 {time} host sshd[4312]: "
        f"Failed password for invalid user admin from {ip} port 41200 ssh2\n"
    )


class ParserTests(unittest.TestCase):
    def test_parses_failed_password(self):
        attempt = parse_attempt(log_line("10:01:00"), 2026)
        self.assertEqual(attempt.ip, "198.51.100.23")
        self.assertEqual(attempt.occurred_at.year, 2026)

    def test_ipv6(self):
        attempt = parse_attempt(log_line("10:00:00", "2001:db8::7"), 2026)
        self.assertEqual(attempt.ip, "2001:db8::7")

    def test_ignores_invalid_user_notice_and_unrelated_lines(self):
        self.assertIsNone(
            parse_attempt("Nov 14 10:01:00 host sshd[1]: Invalid user admin from 198.51.100.23", 2026)
        )
        self.assertIsNone(parse_attempt("hello", 2026))

    def test_rejects_invalid_source_ip(self):
        self.assertIsNone(parse_attempt(log_line("10:00:00", "not-an-ip"), 2026))

    def test_rejects_invalid_timestamp(self):
        self.assertIsNone(parse_attempt(log_line("25:00:00"), 2026))


class DetectionTests(unittest.TestCase):
    def test_detects_threshold_and_peak_window(self):
        findings = analyze_lines(
            [log_line("10:00:00"), log_line("10:01:00"), log_line("10:02:00"), log_line("10:03:00")],
            threshold=3, window_minutes=5, year=2026,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].attempts, 4)

    def test_events_outside_window_are_not_grouped(self):
        findings = analyze_lines(
            [log_line("10:00:00"), log_line("10:06:00"), log_line("10:12:00")],
            threshold=3, window_minutes=5, year=2026,
        )
        self.assertEqual(findings, [])

    def test_group_by_ip_and_sort_unordered_input(self):
        findings = analyze_lines(
            [
                log_line("10:02:00"),
                log_line("10:01:00", "203.0.113.5"),
                log_line("10:00:00"),
                log_line("10:03:00"),
            ],
            threshold=3, window_minutes=5, year=2026,
        )
        self.assertEqual([(item.ip, item.attempts) for item in findings], [("198.51.100.23", 3)])

    def test_rejects_nonpositive_parameters(self):
        with self.assertRaises(ValueError):
            analyze_lines([], threshold=0, year=2026)
        with self.assertRaises(ValueError):
            analyze_lines([], window_minutes=0, year=2026)

    def test_cli_json(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "auth.log"
            log.write_text(log_line("10:00:00") + log_line("10:01:00"), encoding="utf-8")
            buffer = StringIO()
            with redirect_stdout(buffer):
                result = main(["--log", str(log), "--threshold", "2", "--year", "2026", "--json"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(buffer.getvalue())[0]["attempts"], 2)


if __name__ == "__main__":
    unittest.main()
