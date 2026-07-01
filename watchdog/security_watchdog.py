#!/usr/bin/env python3
#
# ----------------------------------------------------------------------
# Raspberry Pi Security Watchdog
# ----------------------------------------------------------------------
#
# Author: H A (i-xul)
# Repository: https://github.com/i-xul/raspberry-pi-security-watchdog
#
# Created: 2026-06-14
# Version: v1.0.0
#
# Description:
# Monitors Raspberry Pi security-relevant logs and services, sends
# Telegram alerts, enriches suspicious activity with GeoIP and Fail2ban
# data, and provides Telegram-based investigation commands.
#
# Version history:
# v1.0.0 - Initial stable monitoring release
#
# ----------------------------------------------------------------------

import ipaddress
import re
import time
import urllib.parse
import urllib.request
import threading
import subprocess
import logging
import gzip
import json
from collections import defaultdict, Counter
from pathlib import Path
from datetime import datetime

import yaml

# =============================================================================
# Logging setup
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("rpi-security-watchdog")

# =============================================================================
# Configuration paths and log parsing patterns
# =============================================================================

CONFIG_PATH = Path("config/config.yaml")

SSH_ACCEPTED_RE = re.compile(
    r"Accepted publickey for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

SSH_PREAUTH_RE = re.compile(
    r"Connection closed by (?P<ip>\S+) port (?P<port>\d+) \[preauth\]"
)

NGINX_ACCESS_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" (?P<status>\d+)'
)

# =============================================================================
# Runtime state
# =============================================================================
# These structures track suspicious activity in memory while the daemon is
# running. Access to shared state is protected with state_lock because several
# watcher threads run at the same time.

suspicious_ips = defaultdict(
    lambda: {
        "count": 0,
        "paths": set(),
        "first_seen": time.time(),
        "last_seen": time.time(),
    }
)

last_alert_times = {}

last_exposed_services = set()

state_lock = threading.RLock()

def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

# =============================================================================
# Telegram integration
# =============================================================================

def send_telegram(bot_token, chat_id, message):
    """
    Send a plain text Telegram message.

    Errors are logged and swallowed so that notification failures do not crash
    the watchdog daemon.
    """

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": message,
    }).encode("utf-8")

    try:
        with urllib.request.urlopen(url, data=data, timeout=10) as response:
            return response.read().decode("utf-8")

    except Exception as error:
        logger.info(f"Telegram notification failed: {error}")
        return None

def get_telegram_updates(bot_token, offset=None, timeout=30):
    url = f"https://api.telegram.org/bot{bot_token}/getUpdates"

    params = {
        "timeout": timeout,
    }

    if offset is not None:
        params["offset"] = offset

    query = urllib.parse.urlencode(params)

    try:
        with urllib.request.urlopen(f"{url}?{query}", timeout=timeout + 5) as response:
            return yaml.safe_load(response.read().decode("utf-8"))
    except Exception as error:
        logger.error(f"Telegram update fetch failed: {error}")
        return None

def build_stats_message(config):
    """
    Build a high-level Telegram summary of scan activity.
    """
    top_ips = get_top_attacker_ips(config, limit=1)
    top_scans = get_top_scan_targets(config, limit=1)

    unique_ips = set()
    total_alerts = 0
    total_requests = 0

    for line in read_watchdog_log_lines(config):
        if "[NGINX_SCAN_ALERT]" not in line:
            continue

        total_alerts += 1

        ip_match = re.search(r"ip=([0-9.]+)", line)
        requests_match = re.search(r"requests=(\d+)", line)

        if ip_match:
            unique_ips.add(ip_match.group(1))

        if requests_match:
            total_requests += int(requests_match.group(1))

    message_lines = [
        "📊 RPi Security Watchdog Stats",
        "",
        f"Total scan alerts: {total_alerts}",
        f"Total scan requests: {total_requests}",
        f"Unique attacker IPs: {len(unique_ips)}",
        "",
    ]

    if top_ips:
        ip = top_ips[0]["ip"]
        geoip = lookup_geoip(config, ip)

        ip_display = ip

        if geoip and geoip.get("flag"):
            ip_display = f"{ip} {geoip['flag']}"

        message_lines.extend([
            "Top attacker:",
            ip_display,
            f"Alerts: {top_ips[0]['alerts']}",
            f"Requests: {top_ips[0]['requests']}",
            "",
        ])

    if top_scans:
        message_lines.extend([
            "Top scan target:",
            top_scans[0]["target"],
            f"Hits: {top_scans[0]['count']}",
        ])

    return "\n".join(message_lines)

def build_geoip_summary_message(config, limit=10):
    country_counts = Counter()

    for line in read_watchdog_log_lines(config):
        if "[NGINX_SCAN_ALERT]" not in line:
            continue

        ip_match = re.search(r"ip=([0-9.]+)", line)

        if not ip_match:
            continue

        ip = ip_match.group(1)
        geoip = lookup_geoip(config, ip)

        if not geoip:
            continue

        country = geoip.get("country", "Unknown")
        flag = geoip.get("flag", "")

        label = f"{flag} {country}".strip()
        country_counts[label] += 1

    if not country_counts:
        return "No GeoIP country statistics available yet."

    lines = [
        "🌍 GeoIP country summary",
        "",
    ]

    for country, count in country_counts.most_common(limit):
        lines.append(f"{country} — {count} alerts")

    return "\n".join(lines)

# =============================================================================
# Persistent event logging and log file following
# =============================================================================

def write_event_log(config, event_type, message):
    """
    Append a structured watchdog event to the persistent event log.
    """
    log_path = Path(config["logs"].get("watchdog_log", "logs/security_watchdog.log"))
    log_path.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().isoformat(timespec="seconds")

    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"{timestamp} [{event_type}] {message}\n")

def ip_allowed(ip, allowed_networks):
    ip_obj = ipaddress.ip_address(ip)

    for network in allowed_networks:
        if ip_obj in ipaddress.ip_network(network, strict=False):
            return True

    return False


def follow_file(path):
    """
    Append a structured watchdog event to the persistent event log.
    """
    path = Path(path)

    while True:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)
                current_inode = path.stat().st_ino

                while True:
                    line = f.readline()

                    if line:
                        yield line.rstrip("\n")
                        continue

                    try:
                        latest_inode = path.stat().st_ino
                    except FileNotFoundError:
                        time.sleep(1)
                        break

                    if latest_inode != current_inode:
                        logger.info(f"Log rotation detected: {path}")
                        break

                    time.sleep(0.5)

        except FileNotFoundError:
            logger.info(f"Log file not found, waiting: {path}")
            time.sleep(2)

# =============================================================================
# Nginx scan detection
# =============================================================================

def contains_unicode(value):
    return any(ord(char) > 127 for char in value)

def should_send_alert(ip, cooldown_minutes):
    now = time.time()
    cooldown_seconds = cooldown_minutes * 60

    with state_lock:
        last_alert = last_alert_times.get(ip)

    if last_alert is None:
        with state_lock:
            last_alert_times[ip] = now
            return True

    if now - last_alert >= cooldown_seconds:
        with state_lock:
            last_alert_times[ip] = now
            return True

    return False

def handle_nginx_line(line, config):
    """
    Parse one Nginx access log line, track suspicious paths per source IP,
    and send an alert when the configured threshold is reached.
    """
    match = NGINX_ACCESS_RE.search(line)

    if not match:
        return

    ip = match.group("ip")
    method = match.group("method")
    path = match.group("path")
    status = match.group("status")

    nginx_config = config.get("nginx", {})
    suspicious_patterns = nginx_config.get("suspicious_patterns", [])
    alert_threshold = nginx_config.get("alert_threshold", 10)
    cooldown_minutes = nginx_config.get("cooldown_minutes", 30)

    for pattern in suspicious_patterns:
        if pattern.lower() in path.lower():
            with state_lock:
                suspicious_ips[ip]["count"] += 1
                suspicious_ips[ip]["paths"].add(path)
                suspicious_ips[ip]["last_seen"] = time.time()

            count = suspicious_ips[ip]["count"]

            logger.info(
                f"Suspicious Nginx request: "
                f"ip={ip} count={count} "
                f"path={path}"
            )

            if count >= alert_threshold and should_send_alert(ip, cooldown_minutes):
                hostname = config.get("hostname", "raspberrypi")
                telegram = config["telegram"]

                example_paths = list(suspicious_ips[ip]["paths"])[:5]
                examples = "\n".join(f"- {example}" for example in example_paths)

                geoip = lookup_geoip(config, ip)
                ip_display = ip

                if geoip and geoip.get("flag"):
                    ip_display = f"{ip} {geoip['flag']}"

                fail2ban_jail = get_fail2ban_status(ip)

                fail2ban_text = ""

                if fail2ban_jail:
                    fail2ban_text = (
                        "\n"
                        "Fail2ban: banned\n"
                        f"Jail: {fail2ban_jail}\n"
                    )

                message = (
                    "⚠️ RPi Security Watchdog\n\n"
                    "Suspicious web scan detected\n\n"
                    f"Host: {hostname}\n"
                    f"IP: {ip_display}\n"
                    f"Requests: {count}\n\n"
                    f"{fail2ban_text}\n"
                    f"Examples:\n{examples}"
                )

                send_telegram(
                    telegram["bot_token"],
                    telegram["chat_id"],
                    message,
                )

                logger.info(f"Telegram alert sent for suspicious Nginx activity: ip={ip}")
                write_event_log(
                    config,
                    "NGINX_SCAN_ALERT",
                    f"ip={ip} requests={count} examples={','.join(example_paths)}"
                )

            return

    unicode_config = nginx_config.get("unicode_detection", {})

    if unicode_config.get("enabled", False) and contains_unicode(path):
        logger.info(
            f"Interesting Unicode request: ip={ip} "
            f"method={method} path={path} status={status}"
        )

# =============================================================================
# SSH monitoring
# =============================================================================

def handle_line(line, config):
    """
    Parse one auth.log line and alert when a successful SSH login comes from
    outside the configured allowed networks.
    """
    accepted_match = SSH_ACCEPTED_RE.search(line)

    if accepted_match:

        user = accepted_match.group("user")
        ip = accepted_match.group("ip")
        port = accepted_match.group("port")

        allowed_networks = config["allowed_networks"]

        if ip_allowed(ip, allowed_networks):
            logger.info(f"Allowed SSH login: user={user} ip={ip}")
            return

        hostname = config.get("hostname", "raspberrypi")
        telegram = config["telegram"]

        message = (
            "🚨 RPi Security Watchdog\n\n"
            "SSH login from non-whitelisted IP\n\n"
            f"Host: {hostname}\n"
            f"User: {user}\n"
            f"IP: {ip}\n"
            f"Port: {port}\n"
        )

        send_telegram(
            telegram["bot_token"],
            telegram["chat_id"],
            message,
        )

        logger.info(f"ALERT SSH login: user={user} ip={ip}")
        write_event_log(
            config,
            "SSH_LOGIN_ALERT",
            f"user={user} ip={ip} port={port}"
        )
        return

    preauth_match = SSH_PREAUTH_RE.search(line)

    if preauth_match:
        ip = preauth_match.group("ip")
        port = preauth_match.group("port")

        if ip_allowed(ip, config["allowed_networks"]):
            return

        logger.info(f"SSH pre-auth connection: ip={ip} port={port}")
        return

# =============================================================================
# Samba monitoring
# =============================================================================

def check_samba_client_logs(config):
    samba_config = config.get("samba", {})

    if not samba_config.get("enabled", False):
        return

    if not samba_config.get("alert_on_unknown_client_logs", False):
        return

    max_log_age_days = samba_config.get("max_log_age_days", 7)

    log_dir = Path(samba_config.get("log_dir", "/var/log/samba"))
    allowed_networks = config["allowed_networks"]

    if not log_dir.exists():
        logger.info(f"Samba log directory not found: {log_dir}")
        return

    unknown_clients = []

    for log_file in log_dir.glob("log.*"):

        age_days = (
            time.time() - log_file.stat().st_mtime
        ) / 86400

        if age_days > max_log_age_days:
            continue

        suffix = log_file.name.replace("log.", "", 1)

        try:
            ipaddress.ip_address(suffix)
        except ValueError:
            continue

        if not ip_allowed(suffix, allowed_networks):
            unknown_clients.append(suffix)

    if not unknown_clients:
        logger.info("Samba client log check: no unknown client logs found")
        return

    hostname = config.get("hostname", "raspberrypi")
    telegram = config["telegram"]

    message_lines = [
        "⚠️ RPi Security Watchdog",
        "",
        "Unknown Samba client log detected",
        "",
        f"Host: {hostname}",
        "",
    ]

    for ip in unknown_clients[:10]:
        message_lines.append(f"- {ip}")

    message = "\n".join(message_lines)

    send_telegram(
        telegram["bot_token"],
        telegram["chat_id"],
        message,
    )

    for ip in unknown_clients:
        logger.info(f"Unknown Samba client log found: ip={ip}")
        write_event_log(
            config,
            "SAMBA_UNKNOWN_CLIENT_LOG",
            f"ip={ip}"
        )

# =============================================================================
# Service exposure monitoring
# =============================================================================

def check_service_exposure(config):
    exposure_config = config.get("service_exposure", {})

    if not exposure_config.get("enabled", False):
        return

    risky_ports = exposure_config.get("risky_ports", {})

    try:
        result = subprocess.run(
            ["ss", "-tulpn"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        logger.info(f"Service exposure check failed: {error}")
        return

    exposed_services = {}

    for line in result.stdout.splitlines():
        for port, service_name in risky_ports.items():
            if re.search(rf"[:\]]{port}\b", line):
                if "127.0.0.1" in line or "[::1]" in line:
                    continue

                key = (port, service_name)
                exposed_services[key] = line.strip()

    if not exposed_services:
        logger.info("Service exposure check: no risky services exposed")
        return

    current_exposed_services = set(exposed_services.keys())

    global last_exposed_services

    with state_lock:
        if current_exposed_services == last_exposed_services:
            logger.info("Service exposure check: no changes")
            return

        last_exposed_services = current_exposed_services

    hostname = config.get("hostname", "raspberrypi")
    telegram = config["telegram"]

    message_lines = [
        "⚠️ RPi Security Watchdog",
        "",
        "Risky service exposure detected",
        "",
        f"Host: {hostname}",
        "",
    ]

    for port, service_name in exposed_services.keys():
        message_lines.append(f"- {service_name} on port {port}")

    message = "\n".join(message_lines)

    send_telegram(
        telegram["bot_token"],
        telegram["chat_id"],
        message,
    )

    for (port, service_name), line in exposed_services.items():
        logger.info(f"Risky service exposed: {service_name} port={port}")
        write_event_log(
            config,
            "SERVICE_EXPOSURE",
            f"service={service_name} port={port} line={line}"
        )

def cleanup_tracked_ips(config):
    nginx_config = config.get("nginx", {})
    cleanup_interval = nginx_config.get("cleanup_interval_seconds", 300)
    ttl_seconds = nginx_config.get("tracked_ip_ttl_minutes", 60) * 60

    while True:
        now = time.time()
        removed_ips = []

        with state_lock:
            for ip, data in list(suspicious_ips.items()):
                if now - data["last_seen"] > ttl_seconds:
                    removed_ips.append(ip)
                    del suspicious_ips[ip]

        for ip in removed_ips:
            with state_lock:
                last_alert_times.pop(ip, None)

        with state_lock:
            if removed_ips:
                logger.info(f"Cleaned up tracked IPs: count={len(removed_ips)}")

        time.sleep(cleanup_interval)

# =============================================================================
# NFS client monitoring
# =============================================================================

def check_nfs_clients(config):
    nfs_config = config.get("nfs", {})

    if not nfs_config.get("enabled", False):
        return

    if not nfs_config.get("alert_on_unknown_clients", False):
        return

    try:
        result = subprocess.run(
            ["ss", "-tn", "sport", "=", ":2049"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        logger.info(f"NFS client check failed: {error}")
        return

    allowed_networks = config["allowed_networks"]
    unknown_clients = set()
    seen_clients = set()

    for line in result.stdout.splitlines():
        if "Peer Address:Port" in line:
            continue

        parts = line.split()

        if len(parts) < 5:
            continue

        peer = parts[4]
        peer_ip = peer.rsplit(":", 1)[0]

        try:
            ipaddress.ip_address(peer_ip)
        except ValueError:
            continue

        seen_clients.add(peer_ip)

        if not ip_allowed(peer_ip, allowed_networks):
            unknown_clients.add(peer_ip)

    if seen_clients:
        logger.info(f"NFS clients seen: {', '.join(sorted(seen_clients))}")

    if not unknown_clients:
        return

    hostname = config.get("hostname", "raspberrypi")
    telegram = config["telegram"]

    message_lines = [
        "⚠️ RPi Security Watchdog",
        "",
        "Unknown NFS client detected",
        "",
        f"Host: {hostname}",
        "",
    ]

    for ip in sorted(unknown_clients):
        message_lines.append(f"- {ip}")

    message = "\n".join(message_lines)

    send_telegram(
        telegram["bot_token"],
        telegram["chat_id"],
        message,
    )

    for ip in sorted(unknown_clients):
        logger.info(f"Unknown NFS client detected: ip={ip}")
        write_event_log(
            config,
            "NFS_UNKNOWN_CLIENT",
            f"ip={ip}"
        )


def watch_nfs_clients(config):
    nfs_config = config.get("nfs", {})
    check_interval = nfs_config.get("check_interval_seconds", 300)

    while True:
        check_nfs_clients(config)
        time.sleep(check_interval)

def watch_service_exposure(config):
    exposure_config = config.get("service_exposure", {})
    check_interval = exposure_config.get("check_interval_seconds", 21600)

    while True:
        check_service_exposure(config)
        time.sleep(check_interval)

def watch_ssh(config):
    auth_log = config["logs"]["auth_log"]

    logger.info(f"Watching SSH log: {auth_log}")

    for line in follow_file(auth_log):
        handle_line(line, config)


def watch_nginx(config):
    nginx_access_log = config["logs"]["nginx_access_log"]

    logger.info(f"Watching Nginx access log: {nginx_access_log}")

    for line in follow_file(nginx_access_log):
        handle_nginx_line(line, config)

def send_startup_notification(config):
    hostname = config.get("hostname", "raspberrypi")
    telegram = config["telegram"]

    message = (
        "🟢 RPi Security Watchdog started\n\n"
        f"Host: {hostname}\n"
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    send_telegram(
        telegram["bot_token"],
        telegram["chat_id"],
        message,
    )

    write_event_log(
        config,
        "WATCHDOG_STARTUP",
        f"host={hostname}"
    )

def read_watchdog_log_lines(config):
    log_path = Path(config["logs"].get("watchdog_log", "logs/security_watchdog.log"))
    log_files = sorted(log_path.parent.glob(f"{log_path.name}*"))

    for path in log_files:
        if path.suffix == ".gz":
            opener = gzip.open
            mode = "rt"
        else:
            opener = open
            mode = "r"

        try:
            with opener(path, mode, encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line.rstrip("\n")
        except FileNotFoundError:
            continue

# =============================================================================
# GeoIP enrichment
# =============================================================================

def country_code_to_flag(country_code):
    if not country_code or len(country_code) != 2:
        return ""

    return "".join(
        chr(127397 + ord(char.upper()))
        for char in country_code
    )


def load_geoip_cache(config):
    cache_path = Path(config.get("geoip", {}).get("cache_file", "logs/geoip_cache.json"))

    if not cache_path.exists():
        return {}

    try:
        with cache_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as error:
        logger.error(f"Failed to load GeoIP cache: {error}")
        return {}


def save_geoip_cache(config, cache):
    cache_path = Path(config.get("geoip", {}).get("cache_file", "logs/geoip_cache.json"))
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with cache_path.open("w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, sort_keys=True)
    except Exception as error:
        logger.error(f"Failed to save GeoIP cache: {error}")


def lookup_geoip(config, ip):
    """
    Resolve an IP address to country information and cache the result locally
    to avoid repeated external API lookups.
    """
    geoip_config = config.get("geoip", {})

    if not geoip_config.get("enabled", False):
        return None

    if ip_allowed(ip, config["allowed_networks"]):
        return None

    cache = load_geoip_cache(config)

    if ip in cache:
        return cache[ip]

    timeout = geoip_config.get("timeout_seconds", 5)
    url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,query"

    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))

    except Exception as error:
        logger.error(f"GeoIP lookup failed for ip={ip}: {error}")
        return None

    if data.get("status") != "success":
        logger.warning(f"GeoIP lookup returned non-success for ip={ip}: {data}")
        return None

    geoip_result = {
        "country": data.get("country", "Unknown"),
        "country_code": data.get("countryCode", ""),
        "flag": country_code_to_flag(data.get("countryCode", "")),
    }

    cache[ip] = geoip_result
    save_geoip_cache(config, cache)

    return geoip_result

# =============================================================================
# Fail2ban correlation
# =============================================================================

def get_fail2ban_status(ip):
    """
    Check whether an IP address is currently banned by any Fail2ban jail.

    The daemon uses sudo -n with a narrow sudoers rule so this check fails
    safely instead of waiting for a password.
    """
    try:
        result = subprocess.run(
            ["sudo", "-n", "fail2ban-client", "status"],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return None

    jail_match = re.search(r"Jail list:\s*(.+)", result.stdout)

    if not jail_match:
        return None

    jails = [
        jail.strip()
        for jail in jail_match.group(1).split(",")
    ]

    for jail in jails:
        try:
            jail_status = subprocess.run(
                ["sudo", "-n", "fail2ban-client", "status", jail],
                capture_output=True,
                text=True,
                check=True,
            )

            if ip in jail_status.stdout:
                return jail

        except Exception:
            continue

    return None

# =============================================================================
# Statistics and Telegram report builders
# =============================================================================

def get_top_attacker_ips(config, limit=10):
    """
    Build attacker statistics from persisted watchdog logs.
    """
    alert_counts = Counter()
    request_counts = Counter()

    for line in read_watchdog_log_lines(config):
        if "[NGINX_SCAN_ALERT]" not in line:
            continue

        ip_match = re.search(r"ip=([0-9.]+)", line)
        requests_match = re.search(r"requests=(\d+)", line)

        if not ip_match:
            continue

        ip = ip_match.group(1)

        if ip_allowed(ip, config["allowed_networks"]):
            continue

        requests = int(requests_match.group(1)) if requests_match else 0

        alert_counts[ip] += 1
        request_counts[ip] += requests

    results = []

    for ip, alerts in alert_counts.most_common(limit):
        results.append({
            "ip": ip,
            "alerts": alerts,
            "requests": request_counts[ip],
        })

    return results

def get_top_scan_targets(config, limit=10):
    target_counts = Counter()

    for line in read_watchdog_log_lines(config):
        if "[NGINX_SCAN_ALERT]" not in line:
            continue

        examples_match = re.search(r"examples=(.+)$", line)

        if not examples_match:
            continue

        for target in examples_match.group(1).split(","):
            target = target.strip()

            if not target:
                continue

            target_counts[target] += 1

    results = []

    for target, count in target_counts.most_common(limit):
        results.append({
            "target": target,
            "count": count,
        })

    return results

def build_top_ips_message(config, limit=10):
    results = get_top_attacker_ips(config, limit)

    if not results:
        return "No attacker IP statistics available yet."

    lines = [
        "📊 Top attacker IPs",
        "",
    ]

    for index, item in enumerate(results, start=1):
        lines.append(
            f"{index}. {item['ip']} — alerts={item['alerts']} requests={item['requests']}"
        )

    return "\n".join(lines)

def build_top_scans_message(config, limit=10):
    results = get_top_scan_targets(config, limit)

    if not results:
        return "No scan target statistics available yet."

    lines = [
        "🎯 Top scan targets",
        "",
    ]

    for index, item in enumerate(results, start=1):
        lines.append(
            f"{index}. {item['target']} — {item['count']} hits"
        )

    return "\n".join(lines)

def build_recent_events_message(config, limit=10):
    events = []

    for line in read_watchdog_log_lines(config):
        if "[NGINX_SCAN_ALERT]" in line:
            event_type = "NGINX"

        elif "[SSH_LOGIN_ALERT]" in line:
            event_type = "SSH"

        elif "[SAMBA_UNKNOWN_CLIENT_LOG]" in line:
            event_type = "SAMBA"

        elif "[NFS_UNKNOWN_CLIENT]" in line:
            event_type = "NFS"

        else:
            continue

        events.append((event_type, line))

    if not events:
        return "No recent watchdog events found."

    events = events[-limit:]

    lines = [
        "📋 Recent watchdog events",
        "",
    ]

    for event_type, line in reversed(events):
        timestamp = line.split(" ")[0]

        if "ip=" in line:
            ip_match = re.search(r"ip=([0-9.]+)", line)
            ip = ip_match.group(1) if ip_match else "unknown"
            lines.append(f"{timestamp} {event_type} {ip}")
        else:
            lines.append(f"{timestamp} {event_type}")

    return "\n".join(lines)

def get_ip_scan_summary(config, target_ip, example_limit=10):
    alerts = 0
    requests_total = 0
    examples = []

    for line in read_watchdog_log_lines(config):
        if "[NGINX_SCAN_ALERT]" not in line:
            continue

        ip_match = re.search(r"ip=([0-9.]+)", line)

        if not ip_match:
            continue

        ip = ip_match.group(1)

        if ip != target_ip:
            continue

        requests_match = re.search(r"requests=(\d+)", line)
        examples_match = re.search(r"examples=(.+)$", line)

        alerts += 1
        requests_total += int(requests_match.group(1)) if requests_match else 0

        if examples_match:
            for example in examples_match.group(1).split(","):
                example = example.strip()
                if example and example not in examples:
                    examples.append(example)

    return {
        "ip": target_ip,
        "alerts": alerts,
        "requests": requests_total,
        "examples": examples[:example_limit],
    }


def build_ip_investigation_message(config, target_ip):
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        return "Invalid IP address."

    summary = get_ip_scan_summary(config, target_ip)
    geoip = lookup_geoip(config, target_ip)

    ip_display = target_ip
    country_line = "Country: unknown"

    if geoip:
        if geoip.get("flag"):
            ip_display = f"{target_ip} {geoip['flag']}"

        if geoip.get("country"):
            country_line = f"Country: {geoip['country']}"

    if summary["alerts"] == 0:
        return (
            "🔎 IP investigation\n\n"
            f"IP: {ip_display}\n"
            f"{country_line}\n\n"
            "No scan alerts found for this IP."
        )

    lines = [
        "🔎 IP investigation",
        "",
        f"IP: {ip_display}",
        country_line,
        "",
        f"Alerts: {summary['alerts']}",
        f"Requests: {summary['requests']}",
        "",
        "Recent examples:",
    ]

    for example in summary["examples"]:
        lines.append(f"- {example}")

    return "\n".join(lines)

def print_top_attacker_ips(config, limit=10):
    results = get_top_attacker_ips(config, limit)

    if not results:
        logger.info("No attacker IP statistics available")
        return

    logger.info("Top attacker IPs:")

    for item in results:
        logger.info(
            f"{item['ip']} alerts={item['alerts']} requests={item['requests']}"
        )

# =============================================================================
# Telegram command polling
# =============================================================================

def watch_telegram_commands(config):
    """
    Poll Telegram for commands from the configured chat and dispatch them to
    the appropriate report builder.
    """
    telegram = config["telegram"]
    bot_token = telegram["bot_token"]
    allowed_chat_id = str(telegram["chat_id"])

    offset = None

    logger.info("Watching Telegram commands")

    while True:
        updates = get_telegram_updates(bot_token, offset=offset, timeout=30)

        if not updates or not updates.get("ok"):
            time.sleep(5)
            continue

        for update in updates.get("result", []):
            offset = update["update_id"] + 1

            message = update.get("message", {})
            chat = message.get("chat", {})
            text = message.get("text", "")
            chat_id = str(chat.get("id", ""))

            if chat_id != allowed_chat_id:
                logger.warning(f"Ignoring Telegram command from unauthorized chat_id={chat_id}")
                continue

            if text == "/top_ips":
                reply = build_top_ips_message(config)
                send_telegram(bot_token, chat_id, reply)
            
            elif text == "/recent":
                reply = build_recent_events_message(config)
                send_telegram(bot_token, chat_id, reply)

            elif text.startswith("/ip "):
                parts = text.split(maxsplit=1)
                target_ip = parts[1].strip()
                reply = build_ip_investigation_message(config, target_ip)
                send_telegram(bot_token, chat_id, reply)

            elif text == "/top_scans":
                reply = build_top_scans_message(config)
                send_telegram(bot_token, chat_id, reply)

            elif text == "/stats":
                reply = build_stats_message(config)
                send_telegram(bot_token, chat_id, reply)

            elif text == "/geoip":
                reply = build_geoip_summary_message(config)
                send_telegram(bot_token, chat_id, reply)

            elif text == "/help":
                reply = (
                    "RPi Security Watchdog commands:\n\n"
                    "/top_ips - show top attacker IPs\n"
                    "/recent - show recent events\n"
                    "/ip <address> - investigate one IP\n"
                    "/top_scans - show most common scan targets\n"
                    "/stats - show overall scan statistics\n"
                    "/geoip - show attacker country summary\n"
                    "/help - show this help message"
                )
                send_telegram(bot_token, chat_id, reply)

# =============================================================================
# Main daemon entry point
# =============================================================================

def main():
    """
    Load configuration, run startup checks, and start all monitoring threads.
    """
    config = load_config()

    send_startup_notification(config)

    # check_service_exposure(config)
    check_samba_client_logs(config)

    ssh_thread = threading.Thread(
        target=watch_ssh,
        args=(config,),
        daemon=True
    )

    exposure_thread = threading.Thread(
        target=watch_service_exposure,
        args=(config,),
        daemon=True
    )

    nfs_thread = threading.Thread(
        target=watch_nfs_clients,
        args=(config,),
        daemon=True
    )

    nginx_thread = threading.Thread(
        target=watch_nginx,
        args=(config,),
        daemon=True
    )

    cleanup_thread = threading.Thread(
        target=cleanup_tracked_ips,
        args=(config,),
        daemon=True
    )

    telegram_thread = threading.Thread(
        target=watch_telegram_commands,
        args=(config,),
        daemon=True
    )

    ssh_thread.start()
    exposure_thread.start()
    nginx_thread.start()
    cleanup_thread.start()
    nfs_thread.start()
    telegram_thread.start()

    logger.info("RPi Security Watchdog started")

    ssh_thread.join()
    exposure_thread.join()
    nginx_thread.join()
    cleanup_thread.join()
    nfs_thread.join()
    telegram_thread.join()

if __name__ == "__main__":
    main()
