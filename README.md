# Raspberry Pi Security Watchdog

Lightweight Raspberry Pi security watchdog for SSH and Nginx monitoring with Telegram alerts.

## Features

* SSH login monitoring
* SSH pre-auth connection detection
* Nginx suspicious request detection
* Telegram alerts for non-whitelisted SSH logins
* Telegram alerts for suspicious web scans
* Per-IP scan tracking and alert thresholds
* Persistent event logging
* Systemd service support
* Logrotate support

## Monitored Events

### SSH

The watchdog monitors:

* Successful SSH logins
* Pre-auth SSH connections
* Logins originating from non-whitelisted networks

### Nginx

The watchdog detects:

* Requests for sensitive files such as:

  * `.env`
  * `.git/config`
  * `wp-config.php`
  * AWS credentials
  * SSH keys
  * Configuration backups

The watchdog groups requests by source IP and sends Telegram alerts when a configurable threshold is reached.

## Requirements

* Raspberry Pi OS or other Linux distribution
* Python 3
* Nginx
* Telegram Bot API token
* Telegram chat ID

## Installation

Clone the repository:

```bash
git clone https://github.com/i-xul/raspberry-pi-security-watchdog.git
cd raspberry-pi-security-watchdog
```

Install dependencies:

```bash
pip3 install pyyaml
```

Create configuration:

```bash
cp config/config.example.yaml config/config.yaml
```

Edit configuration and add:

* Telegram bot token
* Telegram chat ID
* Allowed networks

Start manually:

```bash
python3 watchdog/security_watchdog.py
```

## Systemd Service

Install service:

```bash
sudo cp systemd/raspberry-pi-security-watchdog.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now raspberry-pi-security-watchdog.service
```

Check status:

```bash
systemctl status raspberry-pi-security-watchdog.service
```

## Log Files

Watchdog events are stored in:

```text
logs/security_watchdog.log
```

Systemd logs:

```bash
journalctl -u raspberry-pi-security-watchdog.service -f
```

## License

MIT License

