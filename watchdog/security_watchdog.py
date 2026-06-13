#!/usr/bin/env python3

import ipaddress
import re
import time
import urllib.parse
import urllib.request
import threading
from pathlib import Path

import yaml


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

def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def send_telegram(bot_token, chat_id, message):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": message,
    }).encode("utf-8")

    with urllib.request.urlopen(url, data=data, timeout=10) as response:
        return response.read().decode("utf-8")


def ip_allowed(ip, allowed_networks):
    ip_obj = ipaddress.ip_address(ip)

    for network in allowed_networks:
        if ip_obj in ipaddress.ip_network(network, strict=False):
            return True

    return False


def follow_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            yield line.rstrip("\n")


def contains_unicode(value):
    return any(ord(char) > 127 for char in value)


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

    for pattern in suspicious_patterns:
        if pattern.lower() in path.lower():
            print(
                f"Suspicious Nginx request: ip={ip} "
                f"method={method} path={path} status={status} pattern={pattern}"
            )
            return

    unicode_config = nginx_config.get("unicode_detection", {})

    if unicode_config.get("enabled", False) and contains_unicode(path):
        print(
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
            print(f"Allowed SSH login: user={user} ip={ip}")
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

        print(f"ALERT SSH login: user={user} ip={ip}")
        return

    preauth_match = SSH_PREAUTH_RE.search(line)

    if preauth_match:
        ip = preauth_match.group("ip")
        port = preauth_match.group("port")

        if ip_allowed(ip, config["allowed_networks"]):
            return

        print(f"SSH pre-auth connection: ip={ip} port={port}")
        return

def watch_ssh(config):
    auth_log = config["logs"]["auth_log"]

    print(f"Watching SSH log: {auth_log}")

    for line in follow_file(auth_log):
        handle_line(line, config)


def watch_nginx(config):
    nginx_access_log = config["logs"]["nginx_access_log"]

    print(f"Watching Nginx access log: {nginx_access_log}")

    for line in follow_file(nginx_access_log):
        handle_nginx_line(line, config)

def main():
    config = load_config()

    ssh_thread = threading.Thread(
        target=watch_ssh,
        args=(config,),
        daemon=True
    )

    nginx_thread = threading.Thread(
        target=watch_nginx,
        args=(config,),
        daemon=True
    )

    ssh_thread.start()
    nginx_thread.start()

    print("RPi Security Watchdog started")

    ssh_thread.join()
    nginx_thread.join()

if __name__ == "__main__":
    main()
