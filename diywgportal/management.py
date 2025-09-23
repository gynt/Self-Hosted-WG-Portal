#!/usr/bin/env python3
"""
apply_peers.py — read peers from SQLite and sync a WireGuard interface.

This script *imports your wg.py* (must be on PYTHONPATH or same folder)
and calls wg.add_peer / wg.remove_peer accordingly.

Actions:
- For all rows in DB with enabled=1 for the target interface:
    - If peer not currently on interface: add it (with AllowedIPs, PSK, Keepalive).
- Optional: remove extraneous peers (present on interface but not enabled in DB).

Usage:
  # Dry-run (show actions)
  sudo ./apply_peers.py --db peers.db --interface wg0 --dry-run

  # Apply changes (add missing enabled peers)
  sudo ./apply_peers.py --db peers.db --interface wg0

  # Also remove peers not enabled/in DB
  sudo ./apply_peers.py --db peers.db --interface wg0 --remove-extraneous
"""

import argparse
from datetime import datetime, timezone
import logging
import sqlite3
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from diywgportal.settings import SETTINGS
from diywgportal.watchdog import _parse_created_at
from diywgportal.wg import get_current_peers

# Import functions from wg.py
try:
    import diywgportal.wg as wg
except ImportError as ex:
    raise SystemExit("ERROR: Could not import wg.py. Place apply_peers.py next to wg.py or adjust PYTHONPATH.") from ex

def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True)



def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def fetch_desired_peers(conn: sqlite3.Connection, interface: str):
    """
    Returns a dict keyed by public_key with attributes from DB for enabled peers.
    """
    now = datetime.now(timezone.utc)
    rows = conn.execute(
        """SELECT public_key, COALESCE(preshared_key,''), allowed_ips, COALESCE(persistent_keepalive, -1), created_at, COALESCE(client_ip,''), name, permanent
             FROM peers
            WHERE interface=? AND enabled=1
         """,
        (interface,),
    ).fetchall()
    desired = {}
    for pub, psk, allowed, keep, created_at, client_ip, name, permanent in rows:
        if permanent or (now - _parse_created_at(created_at)).total_seconds() < SETTINGS.getfloat("Watchdog", "PEER_TIMEOUT_SECONDS"):
            desired[pub] = {
                "preshared_key": psk if psk else None,
                "allowed_ips": allowed,
                "persistent_keepalive": None if keep is None or keep == -1 else int(keep),
                "client_ip": client_ip,
                "name": name,
            }
    return desired

def sync_db_to_wg(conn: sqlite3.Connection, interface: str):
    wg.require_binary("wg")

    desired = fetch_desired_peers(conn, interface)
    currentKeyIPs = get_current_peers(interface)
    for pubk, ip in currentKeyIPs.items():
        if ip:
            if pubk in desired and desired[pubk]['client_ip']:
                old_ip = desired[pubk]['client_ip']
                if ip != old_ip:
                    # TODO: currently does not work because people sign up in the 10.112.111.0/24 space but connect with their remote IP
                    #logging.log(logging.DEBUG, f"removing client from desired as IP changed: {pubk}: old ip: {old_ip} new ip: {ip}")
                    #del desired[pubk]
                    pass
    current = set(currentKeyIPs.keys())
    desired_set = set(desired.keys())
    to_add = desired_set - current

    # Remove anything not desired/enabled in DB
    to_remove = current - desired_set

    if not to_add and not to_remove:
        logging.log(logging.DEBUG, "Interface is already in sync.")
        return

    if to_add:
        logging.log(logging.DEBUG, f"Will add {len(to_add)} peer(s):")
        for pub in sorted(to_add):
            meta = desired[pub]
            logging.log(logging.DEBUG, f"  + {meta['name']}: {pub[:16]}…  AllowedIPs={meta['allowed_ips']}  Keepalive={meta['persistent_keepalive']}  PSK={'yes' if meta['preshared_key'] else 'no'}")

    if to_remove:
        logging.log(logging.DEBUG, f"Will remove {len(to_remove)} peer(s):")
        for pub in sorted(to_remove):
            logging.log(logging.DEBUG, f"  - {currentKeyIPs[pub]}: {pub[:16]}…")

    if SETTINGS.getboolean("Debug", "dry_run"):
        logging.log(logging.INFO, "Dry-run only. No changes made.")
        return

    # Apply adds
    for pub in to_add:
        meta = desired[pub]
        wg.add_peer(
            interface=interface,
            peer_pubkey=pub,
            allowed_ips=meta["allowed_ips"],
            preshared_key=meta["preshared_key"],
            persistent_keepalive=meta["persistent_keepalive"],
        )

    # Apply removals
    for pub in to_remove:
        wg.remove_peer(interface, pub)
