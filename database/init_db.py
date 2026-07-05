#!/usr/bin/env python3
#
# ----------------------------------------------------------------------
# Raspberry Pi Security Watchdog - Database Initializer
# ----------------------------------------------------------------------
#
# Author: H A (i-xul)
# Repository: https://github.com/i-xul/raspberry-pi-security-watchdog
#
# Description:
# Initializes the SQLite database used for structured attack history.
#
# ----------------------------------------------------------------------

import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "attack_history.db"


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                requests INTEGER NOT NULL,
                examples TEXT,
                country TEXT,
                country_code TEXT,
                fail2ban_jail TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized: {DB_PATH}")
