import argparse

from diywgportal.management import sync_db_to_wg
from .accounts import add_account, connect as connect_accounts, fetch_accounts, init_db as init_db_accounts, remove_account
from .settings import SETTINGS
from .server import main as serverMain
from .peers import list_peers, connect, init_db, remove_peer, update_or_insert_peer
from .wg import clear_peers
from pathlib import Path
import logging

parser = argparse.ArgumentParser(prog="diywgportal")
parser.add_argument("--dry-run", action='store_true', default=False)
parser.add_argument("--config", default="config.conf")
parser.add_argument("--verbose", default=False, action='store_true')

subparser_actions = parser.add_subparsers(dest="action")
subparser_peers = subparser_actions.add_parser("peers")
subparser_peers.add_argument("peer_action", choices=['add', 'init', 'list', 'clear'])
# subparser_peers.add_argument("--list", default=False, action='store_true')
# subparser_peers.add_argument("--clear", default=False, action='store_true')

subparser_peers.add_argument("--interface")
subparser_peers.add_argument("--name")
subparser_peers.add_argument("--public-key")
subparser_peers.add_argument("--preshared-key")
subparser_peers.add_argument("--allowed-ips")
subparser_peers.add_argument("--keepalive", type=int, dest="persistent_keepalive")
subparser_peers.add_argument("--enabled", action="store_true", default=True)
subparser_peers.add_argument("--disabled", action="store_true", help="Insert as disabled")
subparser_peers.add_argument("--permanent", action="store_true", default=False, help="Insert as permanent")

subparser_accounts = subparser_actions.add_parser("accounts")
subparser_accounts.add_argument("--add", nargs=2)
subparser_accounts.add_argument("--remove", nargs=1)
subparser_accounts.add_argument("--list", default=False, action='store_true')

import io
ss = io.StringIO()

def print_config(path):
  SETTINGS.read(path)
  SETTINGS.write(ss)
  logging.log(logging.DEBUG, ss.getvalue())


def main():
  args = parser.parse_args()
  if args.verbose:
    logging.getLogger().setLevel(logging.DEBUG)
  logging.log(logging.DEBUG, args)
  print_config(args.config)
  SETTINGS.set("Debug", "dry_run", str(args.dry_run))
  
  dbPath = Path(SETTINGS.get("Peers", "database_path")).absolute()
  logging.log(logging.DEBUG, f"database path: {dbPath}")

  if args.action == "peers":
    if args.peer_action == "init":
      with connect(dbPath) as conn:
        init_db(conn)
        return
    if args.peer_action == "add":
      with connect(dbPath) as conn:
        logging.log(logging.INFO, f"adding/updating peer: {args.name} {args.public_key}")
        update_or_insert_peer(conn=conn,
                interface=args.interface,
                name=args.name,
                public_key=args.public_key,
                preshared_key=args.preshared_key,
                allowed_ips=args.allowed_ips,
                persistent_keepalive=args.persistent_keepalive,
                enabled=args.enabled and not args.disabled,
                permanent=args.permanent)
        return
    if args.peer_action == "clear":
      with connect(dbPath) as conn:
        rows = list_peers(conn)
        logging.log(logging.INFO, f"removing peers: {len(rows)}")
        for interface, name, public_key, *rest in rows:
          logging.log(logging.INFO, f"removing peer: {interface}: {name} {public_key}")
          remove_peer(conn, interface=interface, name=name, public_key=public_key)
        return
    if args.peer_action == "list":
      with connect(dbPath) as conn:
        rows = list_peers(conn)
        logging.log(logging.DEBUG, rows)
        if not rows:
          print("(no rows)")
          return
        print("interface,name,public_key,preshared_key,allowed_ips,persistent_keepalive,enabled,created_at")
        for r in rows:
          print(",".join(str(x) for x in r))
        return
    with connect(dbPath) as conn:
      rows = list_peers(conn)
      logging.log(logging.DEBUG, rows)
      if not rows:
        print("(no rows)")
        return
      print("interface,name,public_key,preshared_key,allowed_ips,persistent_keepalive,enabled,created_at")
      for r in rows:
        print(",".join(str(x) for x in r))
      return
  
  if args.action == 'accounts':
    accountsPath = Path(SETTINGS.get("Accounts", "database_path"))
    if args.list:
      for account in fetch_accounts(SETTINGS.get("General", "interface")):
        print(account)
      return
    elif args.add:
      if len(args.add) != 2:
        raise Exception(args.add)
      account_name, account_public_id = args.add
      with connect_accounts(accountsPath) as conn:
        init_db_accounts(conn)
        accounts = fetch_accounts(SETTINGS.get("General", "interface"))
        matches = [acc for acc in accounts if acc.name == account_name or acc.public_id == account_public_id]
        if len(matches) > 0:
          logging.log(logging.ERROR, f"cannot add duplicate account: {account_name} {account_public_id}")
          exit(1)
        logging.log(logging.INFO, f"adding account: {account_name} {account_public_id}")
        add_account(conn=conn, name=account_name, public_id = account_public_id, interface=SETTINGS.get("General", "interface"))
        return
    elif args.remove:
      account_name = args.remove
      with connect_accounts(accountsPath) as conn:
        init_db_accounts(conn)
        logging.log(logging.INFO, f"removing account: {account_name}")
        remove_account(conn=conn, interface=SETTINGS.get("General", "interface"), name=account_name)

  with connect(dbPath) as conn:
    init_db(conn)

    interface = SETTINGS.get("General", "interface")

    # First, sync database to the device
    sync_db_to_wg(conn, interface)

    # Finally, run the server
    serverMain(conn, interface)

if __name__ == "__main__":
  main()