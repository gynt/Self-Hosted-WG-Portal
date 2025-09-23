#!/usr/bin/env python3
"""
peers_db.py — minimal SQLite registry for WireGuard peers.

Schema (table: peers):
- id INTEGER PRIMARY KEY
- interface TEXT NOT NULL         # e.g. 'wg0'
- name TEXT NOT NULL              # human-friendly
- public_key TEXT NOT NULL        # base64
- preshared_key TEXT              # base64 or NULL
- allowed_ips TEXT NOT NULL       # e.g. '10.0.0.2/32'
- persistent_keepalive INTEGER    # seconds or NULL
- enabled INTEGER NOT NULL        # 1 (default) or 0
- created_at TEXT NOT NULL        # ISO timestamp

Uniqueness:
- UNIQUE(interface, public_key)
- UNIQUE(interface, name)

Usage examples:
  # Create DB & table (idempotent)
  ./peers_db.py init --db peers.db

  # Add peer
  ./peers_db.py add --db peers.db --interface wg0 --name alice \
      --public-key BASE64_PUBKEY --allowed-ips 10.0.0.2/32 \
      --preshared-key BASE64_PSK --keepalive 25 --enabled

  # List peers for wg0
  ./peers_db.py list --db peers.db --interface wg0

  # Disable a peer by name
  ./peers_db.py disable --db peers.db --interface wg0 --name alice

  # Remove a peer by public key
  ./peers_db.py remove --db peers.db --interface wg0 --public-key BASE64_PUBKEY

Note: keys are NOT generated here—this is just a registry. Generate keys with wg or wg_manager, then store here.
"""

import argparse
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

DDL = """
CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY,
    interface TEXT NOT NULL,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    preshared_key TEXT,
    allowed_ips TEXT NOT NULL,
    persistent_keepalive INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    client_ip TEXT,
    permanent INTEGER NOT NULL DEFAULT 0,
    UNIQUE(interface, public_key),
    UNIQUE(interface, name)
);
"""

def init_db(conn: sqlite3.Connection):
    conn.executescript(DDL)
    conn.commit()

def now_string():
    return datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z"

def add_peer(conn: sqlite3.Connection, **kw):
    now = now_string()
    conn.execute(
        """INSERT INTO peers
           (interface, name, public_key, preshared_key, allowed_ips, persistent_keepalive, enabled, created_at, client_ip, permanent)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            kw["interface"], kw["name"], kw["public_key"],
            kw.get("preshared_key"),
            kw["allowed_ips"],
            kw.get("persistent_keepalive"),
            1 if kw.get("enabled", True) else 0,
            now,
            kw.get("client_ip"),
            0,
        ),
    )
    conn.commit()

def update_peer(conn: sqlite3.Connection, id: str, **kw):
    now = now_string()
    conn.execute(
    """UPDATE peers SET
        interface=?, name=?, public_key=?, preshared_key=?, allowed_ips=?, persistent_keepalive=?, enabled=?, created_at=?, client_ip=?, permanent=?
        WHERE id =?
        """,
    (
        kw["interface"], kw["name"], kw["public_key"],
        kw.get("preshared_key"),
        kw["allowed_ips"],
        kw.get("persistent_keepalive"),
        1 if kw.get("enabled", True) else 0,
        now,
        kw.get("client_ip"),
        1 if kw.get("permanent", True) else 0,
        id
    ),
    )
    conn.commit()

def update_or_insert_peer(conn: sqlite3.Connection, interface: str, name: str, **kw):
    cur = conn.execute("SELECT id FROM peers WHERE name = ? AND interface = ?", (name, interface, ))
    rows = cur.fetchall()
    if len(rows) > 0:
        id = rows[0][0]
        return update_peer(conn, id=id, interface=interface, name=name, **kw)
    return add_peer(conn, interface=interface, name=name, **kw)

def remove_peer(conn: sqlite3.Connection, interface: str, name: str | None = None, public_key: str | None = None):
    # if not (name or public_key) or (name and public_key):
    #     raise SystemExit("Specify exactly one of --name or --public-key")
    if name:
        conn.execute("DELETE FROM peers WHERE interface=? AND name=?", (interface, name))
    else:
        conn.execute("DELETE FROM peers WHERE interface=? AND public_key=?", (interface, public_key))
    conn.commit()

def set_enabled(conn: sqlite3.Connection, interface: str, enabled: bool, name: str | None = None, public_key: str | None = None):
    if not (name or public_key) or (name and public_key):
        raise SystemExit("Specify exactly one of --name or --public-key")
    if name:
        conn.execute("UPDATE peers SET enabled=? WHERE interface=? AND name=?", (1 if enabled else 0, interface, name))
    else:
        conn.execute("UPDATE peers SET enabled=? WHERE interface=? AND public_key=?", (1 if enabled else 0, interface, public_key))
    conn.commit()

def list_peers(conn: sqlite3.Connection, interface: str | None = None, only_enabled: bool = False):
    q = "SELECT interface, name, public_key, COALESCE(preshared_key,''), allowed_ips, COALESCE(persistent_keepalive,''), enabled, created_at FROM peers"
    conds = []
    args = []
    if interface:
        conds.append("interface=?")
        args.append(interface)
    if only_enabled:
        conds.append("enabled=1")
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " ORDER BY interface, name"
    cur = conn.execute(q, args)
    rows = cur.fetchall()
    return rows


def build_parser():
    p = argparse.ArgumentParser(description="SQLite registry for WireGuard peers")
    p.add_argument("--db", type=Path, default=Path("peers.db"), help="Path to SQLite database file (default: peers.db)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="Create the database schema if missing")

    sp = sub.add_parser("add", help="Insert a peer")
    sp.add_argument("--interface", required=True)
    sp.add_argument("--name", required=True)
    sp.add_argument("--public-key", required=True)
    sp.add_argument("--preshared-key")
    sp.add_argument("--allowed-ips", required=True)
    sp.add_argument("--keepalive", type=int, dest="persistent_keepalive")
    sp.add_argument("--enabled", action="store_true", default=True)
    sp.add_argument("--disabled", action="store_true", help="Insert as disabled")
    sp.add_argument("--permanent", action="store_true", default=False, help="Insert as permanent")
    
    sp = sub.add_parser("remove", help="Delete a peer")
    sp.add_argument("--interface", required=True)
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--name")
    g.add_argument("--public-key")

    sp = sub.add_parser("enable", help="Enable a peer")
    sp.add_argument("--interface", required=True)
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--name")
    g.add_argument("--public-key")

    sp = sub.add_parser("disable", help="Disable a peer")
    sp.add_argument("--interface", required=True)
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--name")
    g.add_argument("--public-key")

    sp = sub.add_parser("list", help="List peers")
    sp.add_argument("--interface")
    sp.add_argument("--only-enabled", action="store_true")

    return p

def main():
    args = build_parser().parse_args()
    conn = connect(args.db)

    if args.cmd == "init":
        init_db(conn)
        print(f"Initialized schema in {args.db}")

    elif args.cmd == "add":
        enabled_flag = args.enabled and not args.disabled
        try:
            add_peer(
                conn,
                interface=args.interface,
                name=args.name,
                public_key=args.public_key,
                preshared_key=args.preshared_key,
                allowed_ips=args.allowed_ips,
                persistent_keepalive=args.persistent_keepalive,
                enabled=enabled_flag,
                permanent=args.permanent
            )
            print(f"Added {args.name} to {args.interface}")
        except sqlite3.IntegrityError as ex:
            raise SystemExit(f"IntegrityError: {ex}")

    elif args.cmd == "remove":
        remove_peer(conn, args.interface, name=args.name, public_key=args.public_key)
        print("Removed.")

    elif args.cmd == "enable":
        set_enabled(conn, args.interface, True, name=args.name, public_key=args.public_key)
        print("Enabled.")

    elif args.cmd == "disable":
        set_enabled(conn, args.interface, False, name=args.name, public_key=args.public_key)
        print("Disabled.")

    elif args.cmd == "list":
        list_peers(conn, interface=args.interface, only_enabled=args.only_enabled)

if __name__ == "__main__":
    main()
