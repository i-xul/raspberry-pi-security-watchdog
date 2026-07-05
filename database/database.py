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

def get_scan_stats():
    """
    Return high-level scan statistics from the SQLite event store.
    """
    with get_connection() as conn:
        total_alerts = conn.execute(
            "SELECT COUNT(*) FROM scan_events"
        ).fetchone()[0]

        total_requests = conn.execute(
            "SELECT COALESCE(SUM(requests), 0) FROM scan_events"
        ).fetchone()[0]

        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM scan_events"
        ).fetchone()[0]

        top_attacker = conn.execute(
            """
            SELECT ip, country, country_code, COUNT(*) AS alerts, SUM(requests) AS requests
            FROM scan_events
            GROUP BY ip, country, country_code
            ORDER BY alerts DESC, requests DESC
            LIMIT 1
            """
        ).fetchone()

def get_top_attacker_ips(limit=10):
    """
    Return top attacker IPs from the SQLite event store.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                ip,
                country,
                country_code,
                COUNT(*) AS alerts,
                SUM(requests) AS requests
            FROM scan_events
            GROUP BY ip, country, country_code
            ORDER BY alerts DESC, requests DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return rows

    return {
        "total_alerts": total_alerts,
        "total_requests": total_requests,
        "unique_ips": unique_ips,
        "top_attacker": top_attacker,
    }
