#!/usr/bin/env python3
#
# ----------------------------------------------------------------------
# Raspberry Pi Security Watchdog - Database API
# ----------------------------------------------------------------------
#
# Author: H A (i-xul)
# Repository: https://github.com/i-xul/raspberry-pi-security-watchdog
#
# Description:
# Provides helper functions for writing structured watchdog events to
# the local SQLite attack history database.
#
# ----------------------------------------------------------------------

import sqlite3
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "attack_history.db"

def get_connection():
    """
    Return a SQLite connection to the attack history database.
    """
    return sqlite3.connect(DB_PATH)

def insert_scan_event(
    timestamp,
    ip,
    requests,
    examples=None,
    country=None,
    country_code=None,
    fail2ban_jail=None,
):
    """
    Insert a suspicious Nginx scan event into the attack history database.
    """
    examples_text = ",".join(examples) if isinstance(examples, list) else examples

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_events (
                timestamp,
                ip,
                requests,
                examples,
                country,
                country_code,
                fail2ban_jail
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                ip,
                requests,
                examples_text,
                country,
                country_code,
                fail2ban_jail,
            ),
        )

        conn.commit()


def get_scan_event_count():
    """
    Return the number of stored scan events.
    """
    with get_connection() as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM scan_events")
        return cursor.fetchone()[0]
