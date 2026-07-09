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

# =============================================================================
# Database connection
# =============================================================================

def get_connection():
    """
    Return a SQLite connection to the attack history database.
    """
    return sqlite3.connect(DB_PATH)

# =============================================================================
# Scan event storage
# =============================================================================

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

# =============================================================================
# Scan event queries
# =============================================================================

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

def get_country_summary(limit=10):
    """
    Return attacker country summary from the SQLite event store.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                country,
                country_code,
                COUNT(*) AS alerts
            FROM scan_events
            WHERE country IS NOT NULL
            GROUP BY country, country_code
            ORDER BY alerts DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return rows

def get_top_scan_targets(limit=10):
    """
    Return most common scan targets from the SQLite event store.

    The examples column currently stores comma-separated paths, so this
    function expands them in Python before counting.
    """
    from collections import Counter

    target_counts = Counter()

    with get_connection() as conn:
        rows = conn.execute(
            "SELECT examples FROM scan_events WHERE examples IS NOT NULL"
        ).fetchall()

    for (examples,) in rows:
        if not examples:
            continue

        for target in examples.split(","):
            target = target.strip()

            if not target:
                continue

            target_counts[target] += 1

    return target_counts.most_common(limit)

def get_recent_scan_events(limit=10):
    """
    Return recent scan events from the SQLite event store.
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                timestamp,
                ip,
                country,
                country_code,
                requests,
                fail2ban_jail
            FROM scan_events
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return rows

def get_ip_details(ip):
    """
    Return aggregated information for a single attacker IP.
    """
    with get_connection() as conn:

        summary = conn.execute(
            """
            SELECT
                country,
                country_code,
                COUNT(*) AS alerts,
                SUM(requests) AS requests
            FROM scan_events
            WHERE ip = ?
            GROUP BY country, country_code
            """,
            (ip,),
        ).fetchone()

        examples = conn.execute(
            """
            SELECT examples
            FROM scan_events
            WHERE ip = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()

    if summary is None:
        return None

    return {
        "country": summary[0],
        "country_code": summary[1],
        "alerts": summary[2],
        "requests": summary[3],
        "examples": examples[0] if examples else "",
    }

    return {
        "total_alerts": total_alerts,
        "total_requests": total_requests,
        "unique_ips": unique_ips,
        "top_attacker": top_attacker,
    }

# =============================================================================
# SSH event storage
# =============================================================================

def insert_ssh_event(
    timestamp,
    event_type,
    ip,
    user=None,
    port=None,
    allowed=False,
    country=None,
    country_code=None,
):
    """
    Insert an SSH-related security event into the event database.
    """
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO ssh_events (
                timestamp,
                event_type,
                user,
                ip,
                port,
                allowed,
                country,
                country_code
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event_type,
                user,
                ip,
                port,
                1 if allowed else 0,
                country,
                country_code,
            ),
        )

        conn.commit()