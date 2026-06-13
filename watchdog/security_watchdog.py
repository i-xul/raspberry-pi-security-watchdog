#!/usr/bin/env python3

import ipaddress
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


CONFIG_PATH = Path("config/config.yaml")

SSH_ACCEPTED_RE = re.compile(
    r"Accepted publickey for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
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


def handle_line(line, config):
    match = SSH_ACCEPTED_RE.search(line)

    if not match:
        return

    user = match.group("user")
    ip = match.group("ip")
    port = match.group("port")

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


def main():
    config = load_config()
    auth_log = config["logs"]["auth_log"]

    print(f"Watching SSH log: {auth_log}")

    for line in follow_file(auth_log):
        handle_line(line, config)


if __name__ == "__main__":
    main()
