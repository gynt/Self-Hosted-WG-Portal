
from dataclasses import dataclass
from pathlib import Path
import sqlite3

from diywgportal.settings import SETTINGS

@dataclass
class Account:
    public_id: str
    name: str

def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

DDL = """
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    interface TEXT NOT NULL,
    name TEXT NOT NULL,
    public_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    UNIQUE(interface, public_id),
    UNIQUE(interface, name)
);
"""

def init_db(conn: sqlite3.Connection):
    conn.executescript(DDL)
    conn.commit()


def add_account(conn: sqlite3.Connection, **kw):
    conn.execute(
        """INSERT INTO accounts
           (interface, name, public_id, enabled)
           VALUES (?, ?, ?, ?)""",
        (
            kw["interface"], kw["name"], kw["public_id"], 1
        ),
    )
    conn.commit()

def remove_account(conn: sqlite3.Connection, interface:str, name: str):
    # if not (name or public_key) or (name and public_key):
    #     raise SystemExit("Specify exactly one of --name or --public-key")
    conn.execute("DELETE FROM accounts WHERE interface=? AND name=?", (interface, name))
    conn.commit()

def fetch_desired_accounts(conn: sqlite3.Connection, interface: str):
    """
    Returns a dict keyed by public_id with attributes from DB for enabled accounts.
    """
    rows = conn.execute(
        """SELECT public_id, name
             FROM accounts
            WHERE interface=? AND enabled=1
         """,
        (interface,),
    ).fetchall()

    for public_id, name in rows:
        yield public_id, name

def fetch_accounts(interface: str):
    with connect(Path(SETTINGS.get("Accounts", "DATABASE_PATH"))) as conn:
        init_db(conn=conn)
        for public_id, name in fetch_desired_accounts(conn, interface):
            yield Account(public_id=public_id, name=name)