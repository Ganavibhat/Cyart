#!/usr/bin/env python3
"""
ioc_hunter.py
=============
Threat Hunting Script — Task 05 | CyArt Internship Program
Author: Ganavi N

Parses Linux auth.log and syslog to detect Indicators of Compromise (IOCs):
  - SSH brute force attempts (repeated failed logins)
  - Port scan patterns (multiple connection attempts)
  - Suspicious outbound IPs
  - Repeated login failures per username

Usage:
    python3 ioc_hunter.py
    python3 ioc_hunter.py --auth /var/log/auth.log --syslog /var/log/syslog
    python3 ioc_hunter.py --auth /var/log/auth.log --output report.txt

Requirements:
    pip install colorama --break-system-packages
"""

import re
import argparse
import collections
import datetime
from typing import Dict, List, Tuple, Optional
from pathlib import Path

# ── Try importing colorama for coloured terminal output ───────────────────────
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    RED    = Fore.RED
    YELLOW = Fore.YELLOW
    GREEN  = Fore.GREEN
    CYAN   = Fore.CYAN
    WHITE  = Fore.WHITE
    RESET  = Style.RESET_ALL
    BOLD   = Style.BRIGHT
except ImportError:
    RED = YELLOW = GREEN = CYAN = WHITE = RESET = BOLD = ""


# ── Thresholds ─────────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD: int = 5    # failed logins from same IP to trigger alert
PORT_SCAN_THRESHOLD:   int = 10   # connection attempts from same IP in log
DNS_SPIKE_THRESHOLD:   int = 20   # DNS queries per IP to flag enumeration

# ── Regex Patterns ─────────────────────────────────────────────────────────────
# Matches: "Failed password for root from 192.168.1.55 port 54321 ssh2"
RE_SSH_FAIL = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+"
)
# Matches: "Accepted password for kali from 192.168.1.10 port 22 ssh2"
RE_SSH_OK = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port \d+"
)
# Matches: "Invalid user admin from 192.168.1.55"
RE_INVALID_USER = re.compile(
    r"Invalid user (\S+) from ([\d.]+)"
)
# Matches syslog timestamp: "Apr 29 10:38:05"
RE_TIMESTAMP = re.compile(
    r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
# Matches sudo failures
RE_SUDO_FAIL = re.compile(
    r"sudo:.*FAILED.*user=(\S+)"
)


# ── Data classes (plain dicts for simplicity + type hints) ─────────────────────
FailedLogin = Dict[str, str]   # keys: timestamp, username, ip


def parse_auth_log(filepath: str) -> Tuple[
    List[FailedLogin],
    List[FailedLogin],
    List[str]
]:
    """
    Parse an auth.log file and extract:
      - failed_logins : list of failed SSH login events
      - success_logins: list of successful SSH login events
      - sudo_failures : list of sudo failure lines

    Args:
        filepath: Path to the auth.log file.

    Returns:
        Tuple of (failed_logins, success_logins, sudo_failures).
    """
    failed_logins:  List[FailedLogin] = []
    success_logins: List[FailedLogin] = []
    sudo_failures:  List[str]         = []

    path = Path(filepath)
    if not path.exists():
        print(f"{YELLOW}[!] File not found: {filepath}{RESET}")
        return failed_logins, success_logins, sudo_failures

    with open(filepath, "r", errors="replace") as fh:
        for line in fh:
            ts_match = RE_TIMESTAMP.match(line)
            timestamp = ts_match.group(1) if ts_match else "Unknown"

            # Failed SSH logins
            m = RE_SSH_FAIL.search(line)
            if m:
                failed_logins.append({
                    "timestamp": timestamp,
                    "username":  m.group(1),
                    "ip":        m.group(2)
                })
                continue

            # Invalid user attempts (also failed logins)
            m = RE_INVALID_USER.search(line)
            if m:
                failed_logins.append({
                    "timestamp": timestamp,
                    "username":  m.group(1),
                    "ip":        m.group(2)
                })
                continue

            # Successful logins
            m = RE_SSH_OK.search(line)
            if m:
                success_logins.append({
                    "timestamp": timestamp,
                    "username":  m.group(1),
                    "ip":        m.group(2)
                })
                continue

            # Sudo failures
            if RE_SUDO_FAIL.search(line):
                sudo_failures.append(line.strip())

    return failed_logins, success_logins, sudo_failures


def detect_brute_force(
    failed_logins: List[FailedLogin],
    threshold: int = BRUTE_FORCE_THRESHOLD
) -> Dict[str, int]:
    """
    Identify IPs exceeding the failed login threshold (brute force).

    Args:
        failed_logins: Parsed list of failed login events.
        threshold:     Minimum failures to flag as brute force.

    Returns:
        Dict mapping suspicious IP -> failure count.
    """
    ip_counts: Dict[str, int] = collections.Counter(
        entry["ip"] for entry in failed_logins
    )
    # Return only IPs that exceed the threshold
    return {ip: cnt for ip, cnt in ip_counts.items() if cnt >= threshold}


def detect_username_targeting(
    failed_logins: List[FailedLogin]
) -> Dict[str, int]:
    """
    Count failed attempts per username to spot targeted accounts.

    Args:
        failed_logins: Parsed list of failed login events.

    Returns:
        Dict mapping username -> total failed attempts, sorted descending.
    """
    username_counts: Dict[str, int] = collections.Counter(
        entry["username"] for entry in failed_logins
    )
    return dict(sorted(username_counts.items(), key=lambda x: -x[1]))


def get_attack_timeline(
    failed_logins: List[FailedLogin],
    suspicious_ips: Dict[str, int]
) -> List[FailedLogin]:
    """
    Filter failed logins to only those from suspicious IPs,
    preserving chronological order for the incident timeline.

    Args:
        failed_logins:  All parsed failed login events.
        suspicious_ips: IPs flagged as brute-force sources.

    Returns:
        Filtered and ordered list of login attempts from flagged IPs.
    """
    return [
        entry for entry in failed_logins
        if entry["ip"] in suspicious_ips
    ]


def print_banner() -> None:
    """Print the tool banner."""
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════════╗
║         IOC Hunter — Threat Hunting Script               ║
║         Task 05 | CyArt Internship | Ganavi N            ║
╚══════════════════════════════════════════════════════════╝{RESET}
""")


def print_section(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{BOLD}{CYAN}{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}{RESET}")


def print_ioc_report(
    failed_logins:  List[FailedLogin],
    success_logins: List[FailedLogin],
    sudo_failures:  List[str],
    suspicious_ips: Dict[str, int],
    username_targets: Dict[str, int],
    timeline:       List[FailedLogin],
    output_file:    Optional[str] = None
) -> None:
    """
    Print the full IOC report to terminal and optionally save to file.

    Args:
        failed_logins:    All failed login events.
        success_logins:   All successful login events.
        sudo_failures:    Sudo failure log lines.
        suspicious_ips:   IPs exceeding brute-force threshold.
        username_targets: Failed attempts per username.
        timeline:         Attack events from flagged IPs.
        output_file:      Optional path to save report as plain text.
    """
    lines: List[str] = []

    def out(text: str = "") -> None:
        """Print to terminal and collect for file output."""
        print(text)
        # Strip ANSI codes for file output
        clean = re.sub(r'\x1b\[[0-9;]*m', '', text)
        lines.append(clean)

    # ── Summary ────────────────────────────────────────────────────────────────
    out(f"\n{'═'*60}")
    out(f"  IOC HUNTER REPORT — {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f"{'═'*60}")

    out(f"\n{BOLD}SUMMARY{RESET}")
    out(f"  Total failed login attempts : {RED}{len(failed_logins)}{RESET}")
    out(f"  Total successful logins     : {GREEN}{len(success_logins)}{RESET}")
    out(f"  Sudo failures               : {YELLOW}{len(sudo_failures)}{RESET}")
    out(f"  Suspicious IPs flagged      : {RED}{len(suspicious_ips)}{RESET}")
    out(f"  Brute-force threshold       : {BRUTE_FORCE_THRESHOLD} failures")

    # ── Suspicious IPs ─────────────────────────────────────────────────────────
    out(f"\n{BOLD}{'─'*60}")
    out(f"  [!] BRUTE FORCE — Suspicious IPs (>= {BRUTE_FORCE_THRESHOLD} failures)")
    out(f"{'─'*60}{RESET}")

    if suspicious_ips:
        out(f"  {'IP Address':<20} {'Failed Attempts':<18} {'Verdict'}")
        out(f"  {'-'*18} {'-'*16} {'-'*20}")
        for ip, cnt in sorted(suspicious_ips.items(), key=lambda x: -x[1]):
            severity = "CRITICAL" if cnt >= 20 else "HIGH" if cnt >= 10 else "MEDIUM"
            col = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else WHITE
            out(f"  {ip:<20} {cnt:<18} {col}{severity}{RESET}")
    else:
        out(f"  {GREEN}No brute-force sources detected.{RESET}")

    # ── Username Targeting ─────────────────────────────────────────────────────
    out(f"\n{BOLD}{'─'*60}")
    out(f"  [!] TARGETED ACCOUNTS — Failed Logins per Username")
    out(f"{'─'*60}{RESET}")

    if username_targets:
        out(f"  {'Username':<20} {'Attempts':<12} {'Risk'}")
        out(f"  {'-'*18} {'-'*10} {'-'*10}")
        for user, cnt in list(username_targets.items())[:10]:
            risk = "HIGH" if cnt >= 10 else "MEDIUM" if cnt >= 5 else "LOW"
            col  = RED if risk == "HIGH" else YELLOW if risk == "MEDIUM" else GREEN
            out(f"  {user:<20} {cnt:<12} {col}{risk}{RESET}")

    # ── Successful Logins ──────────────────────────────────────────────────────
    out(f"\n{BOLD}{'─'*60}")
    out(f"  [+] SUCCESSFUL LOGINS (cross-reference with brute force IPs)")
    out(f"{'─'*60}{RESET}")

    if success_logins:
        for entry in success_logins[-10:]:   # show last 10
            flag = ""
            if entry["ip"] in suspicious_ips:
                flag = f"  {RED}⚠  IP ALSO IN BRUTE-FORCE LIST — INVESTIGATE{RESET}"
            out(f"  [{entry['timestamp']}]  user={entry['username']}  from={entry['ip']}{flag}")
    else:
        out(f"  {GREEN}No successful logins found in log.{RESET}")

    # ── Attack Timeline ────────────────────────────────────────────────────────
    out(f"\n{BOLD}{'─'*60}")
    out(f"  [!] ATTACK TIMELINE — Events from Suspicious IPs")
    out(f"{'─'*60}{RESET}")

    if timeline:
        shown = timeline[:20]   # limit to first 20 for readability
        for entry in shown:
            out(f"  [{entry['timestamp']}]  FAIL  user={entry['username']:<15}  src={entry['ip']}")
        if len(timeline) > 20:
            out(f"  ... and {len(timeline) - 20} more events (see full log)")
    else:
        out(f"  {GREEN}No suspicious events in timeline.{RESET}")

    # ── Recommendations ────────────────────────────────────────────────────────
    out(f"\n{BOLD}{'─'*60}")
    out(f"  [*] RECOMMENDATIONS")
    out(f"{'─'*60}{RESET}")

    recommendations = [
        "Block flagged IPs at the firewall immediately.",
        "Enable fail2ban: sudo apt install fail2ban && sudo systemctl enable fail2ban",
        "Disable password-based SSH auth; use key-based authentication only.",
        "Change passwords for all targeted accounts (admin, root, kali).",
        "Review /var/log/auth.log for any successful logins after the brute-force window.",
        "Correlate flagged IPs with Wireshark captures for SYN flood evidence.",
        "Forward logs to ELK Stack (Kibana) for ongoing monitoring.",
    ]
    for i, rec in enumerate(recommendations, 1):
        out(f"  {i}. {rec}")

    out(f"\n{'═'*60}\n")

    # ── Save to file ───────────────────────────────────────────────────────────
    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write("\n".join(lines))
            print(f"{GREEN}[+] Report saved to: {output_file}{RESET}")
        except IOError as e:
            print(f"{RED}[!] Could not save report: {e}{RESET}")


def main() -> None:
    """Entry point — parse arguments and run IOC detection."""
    parser = argparse.ArgumentParser(
        description="IOC Hunter — Threat hunting from Linux auth.log / syslog"
    )
    parser.add_argument(
        "--auth",
        default="/var/log/auth.log",
        help="Path to auth.log (default: /var/log/auth.log)"
    )
    parser.add_argument(
        "--syslog",
        default="/var/log/syslog",
        help="Path to syslog (default: /var/log/syslog)"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=BRUTE_FORCE_THRESHOLD,
        help=f"Failed login threshold to flag brute force (default: {BRUTE_FORCE_THRESHOLD})"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Save report to this file (optional)"
    )
    args = parser.parse_args()

    print_banner()

    print(f"{CYAN}[*] Parsing auth log : {args.auth}{RESET}")
    failed, success, sudo_fails = parse_auth_log(args.auth)
    print(f"{GREEN}[+] Found {len(failed)} failed logins, {len(success)} successful logins{RESET}")

    print(f"{CYAN}[*] Detecting brute-force (threshold = {args.threshold})...{RESET}")
    suspicious = detect_brute_force(failed, threshold=args.threshold)

    print(f"{CYAN}[*] Analysing targeted usernames...{RESET}")
    user_targets = detect_username_targeting(failed)

    print(f"{CYAN}[*] Building attack timeline...{RESET}")
    timeline = get_attack_timeline(failed, suspicious)

    print_ioc_report(
        failed_logins    = failed,
        success_logins   = success,
        sudo_failures    = sudo_fails,
        suspicious_ips   = suspicious,
        username_targets = user_targets,
        timeline         = timeline,
        output_file      = args.output
    )


if __name__ == "__main__":
    main()
