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

import logging
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

import json, ipaddress
# ip: 10.112.111.1
def get_wireguard_interface_name_if_ip_on_wireguard_interface(ip):
    proc = wg.run(cmd=["ip", "-details", "-j", "addr", "show"])
    interfaces = json.loads(proc.stdout)
    for intf in interfaces:
        if "linkinfo" in intf:
            info = intf["linkinfo"]
            if "info_kind" in info:
                kind = info["info_kind"]
                if kind == "wireguard":
                    if "addr_info" in intf:
                        addr_infos = intf["addr_info"]
                        for addr_info in addr_infos:
                            if 'local' in addr_info:
                                local = addr_info['local']
                                # TODO this assumes /24 'the least strict type of network'
                                net = ipaddress.ip_network(f"{local}/24", strict=False)
                                if ipaddress.ip_address(ip) in net:
                                    return intf["ifname"]
    return None

def get_endpoint_ip_on_wireguard_interface(interface: str, ip: str):
    """returns ip:port for an interface and a wireguarded ip address"""
    pubk_ipport_dict = wg.get_current_peers(interface=interface)
    pubk_address_dict = wg.get_allowed_ips(interface=interface, with_slash=False)
    pubk = None
    for candidateP, address in pubk_address_dict.items():
        if address == ip:
            pubk = candidateP
            break
    else:
        return None
    if pubk not in pubk_ipport_dict:
        return None
    v = pubk_ipport_dict[pubk]
    if v is None:
        return None
    return v.split(":", 2)[0]

def get_endpoint_ip_for_ip(ip: str):
    logging.log(logging.DEBUG, f"get_endpoint_ip_for_ip({ip})")
    if not ipaddress.ip_address(ip) in ipaddress.ip_network("10.0.0.0/8"):
        # Assumes remote ip already
        return ip
    intf = get_wireguard_interface_name_if_ip_on_wireguard_interface(ip)
    if not intf:
        return None
    return get_endpoint_ip_on_wireguard_interface(interface=intf, ip=ip)

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
