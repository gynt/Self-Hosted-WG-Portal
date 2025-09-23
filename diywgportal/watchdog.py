#!/usr/bin/env python3
"""
expiry_watchdog.py — Background thread to disconnect expired WireGuard peers.

- Looks in the SQLite 'peers' table created by peers.py
- Any row with enabled=1 and created_at older than int(SETTINGS.get("Watchdog", "PEER_TIMEOUT_SECONDS")) (default 3600)
  is 'disconnected':
     * wg.remove_peer(interface, public_key)
     * enabled set to 0 in DB (soft disable)
- Runs forever (until Ctrl+C), scanning every int(SETTINGS.get("Watchdog", "WATCH_INTERVAL_SECONDS")) seconds (default 60).

Environment variables:
  SETTINGS.get("General", "interface")        (default: wg0)
  WG_Path(SETTINGS.get("Peers", "database_path"))          (default: ./peers.db)
  int(SETTINGS.get("Watchdog", "PEER_TIMEOUT_SECONDS"))      (default: 3600)
  int(SETTINGS.get("Watchdog", "WATCH_INTERVAL_SECONDS"))       (default: 60)

Notes:
- 'created_at' is stored by peers.py as ISO (UTC) like 'YYYY-MM-DDTHH:MM:SSZ'.
- This script only affects live interface + DB 'enabled' flag.
  It does NOT edit /etc/wireguard/<iface>.conf.
"""

import os
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3

# Local modules from your setup
from . import wg
from . import peers
from .settings import SETTINGS

def _utcnow():
    return datetime.now(timezone.utc)

def _parse_created_at(s: str) -> datetime:
    # peers writes like 'YYYY-MM-DDTHH:MM:SSZ'
    # Support both 'Z' and explicit offsets
    if not s.endswith("Z"):
        s = s[:-1] + "+00:00"
    else:
        s = s[:-1]
    return datetime.fromisoformat(s)

def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def _scan_and_disconnect_once(conn: sqlite3.Connection):
    cutoff = _utcnow() - timedelta(seconds=int(SETTINGS.get("Watchdog", "PEER_TIMEOUT_SECONDS")))
    # Select candidates: enabled and older than cutoff
    rows = conn.execute(
        """SELECT interface, name, public_key, COALESCE(preshared_key,''), allowed_ips, 
                  COALESCE(persistent_keepalive,''), enabled, created_at
             FROM peers
            WHERE enabled=1"""
    ).fetchall()

    to_disable = []
    for (iface, name, pubkey, _psk, allowed, _keep, enabled, created_at) in rows:
        try:
            created_dt = _parse_created_at(created_at)
        except Exception:
            # If bad timestamp somehow, skip safely
            continue
        if created_dt <= cutoff:
            to_disable.append((iface, name, pubkey, allowed, created_at))

    if not to_disable:
        return 0

    # Ensure wg exists (raises once, not per peer)
    wg.require_binary("wg")

    disconnected = 0
    for iface, name, pubkey, allowed, created_at in to_disable:
        # Only act on the configured interface; skip others
        if iface != SETTINGS.get("General", "interface"):
            continue
        try:
            wg.remove_peer(SETTINGS.get("General", "interface"), pubkey)
            disconnected += 1
            print(f"[expiry] Disconnected {name} ({pubkey[:16]}…) from {SETTINGS.get('General', 'interface')} "
                  f"(created_at={created_at}, allowed={allowed})")
        except Exception as ex:
            print(f"[expiry] WARN: failed to remove peer {name} ({pubkey[:16]}…): {ex}")

        # Flip enabled=0 regardless (so we don't hammer it next scan)
        try:
            conn.execute(
                "UPDATE peers SET enabled=0 WHERE interface=? AND public_key=?",
                (SETTINGS.get("General", "interface"), pubkey),
            )
            conn.commit()
        except Exception as ex:
            print(f"[expiry] WARN: failed to disable in DB for {name} ({pubkey[:16]}…): {ex}")

    return disconnected

def worker():
    # Keep a persistent connection for simplicity
    conn = _connect(Path(SETTINGS.get("Peers", "database_path")))
    # Ensure schema exists (idempotent)
    peers.init_db(conn)

    print(f"[expiry] watching DB={Path(SETTINGS.get('Peers', 'database_path'))} interface={SETTINGS.get('General', 'interface')} "
          f"expiry={int(SETTINGS.get('Watchdog', 'PEER_TIMEOUT_SECONDS'))}s interval={int(SETTINGS.get('Watchdog', 'WATCH_INTERVAL_SECONDS'))}s")
    while True:
        try:
            n = _scan_and_disconnect_once(conn)
            if n:
                print(f"[expiry] cycle complete: disconnected {n} expired peer(s)")
        except Exception as ex:
            print(f"[expiry] ERROR: scan failed: {ex}")
        time.sleep(int(SETTINGS.get("Watchdog", "WATCH_INTERVAL_SECONDS")))

def main():
    t = threading.Thread(target=worker, name="expiry-watchdog", daemon=True)
    t.start()
    try:
        # Keep the main thread alive so the daemon thread runs
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[expiry] exiting…")

if __name__ == "__main__":
    main()
