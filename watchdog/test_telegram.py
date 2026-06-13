#!/usr/bin/env python3

import urllib.parse
import urllib.request
import yaml

CONFIG_PATH = "config/config.yaml"


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def send_telegram(bot_token, chat_id, message):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": message,
    }).encode("utf-8")

    with urllib.request.urlopen(url, data=data, timeout=10) as response:
        return response.read().decode("utf-8")


def main():
    config = load_config()
    telegram = config["telegram"]

    response = send_telegram(
        telegram["bot_token"],
        telegram["chat_id"],
        "RPi Security Watchdog test alert"
    )

    print(response)


if __name__ == "__main__":
    main()
