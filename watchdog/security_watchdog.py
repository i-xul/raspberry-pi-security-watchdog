#!/usr/bin/env python3

import ipaddress
import re
import time
import urllib.parse
import urllib.request
import threading
import subprocess
import logging
from pathlib import Path
from collections import defaultdict
from datetime import datetime

import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("rpi-security-watchdog")

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


def send_telegram(bot_token, chat_id, message):
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

def write_event_log(config, event_type, message):
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

                message = (
                    "⚠️ RPi Security Watchdog\n\n"
                    "Suspicious web scan detected\n\n"
                    f"Host: {hostname}\n"
                    f"IP: {ip}\n"
                    f"Requests: {count}\n\n"
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

def handle_line(line, config):
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

def main():
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

    ssh_thread.start()
    exposure_thread.start()
    nginx_thread.start()
    cleanup_thread.start()
    nfs_thread.start()

    logger.info("RPi Security Watchdog started")

    ssh_thread.join()
    exposure_thread.join()
    nginx_thread.join()
    cleanup_thread.join()
    nfs_thread.join()

if __name__ == "__main__":
    main()
