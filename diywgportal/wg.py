#!/usr/bin/env python3
"""
wg_manager.py — Minimal WireGuard peer manager using the `wg` CLI.

Features:
- create-config: generate keys and a client .conf for a new peer
- add-peer: add a peer to a running interface (wg set)
- remove-peer: remove a peer from a running interface (wg set ... remove)

Examples:
  sudo ./wg_manager.py create-config wg0 alice --address 10.0.0.2/32 \
       --dns 1.1.1.1 --endpoint vpn.example.com:51820 --out ./peers
  sudo ./wg_manager.py add-peer wg0 <peer_pubkey> --allowed-ips 10.0.0.2/32
  sudo ./wg_manager.py remove-peer wg0 <peer_pubkey>

Notes:
- For atomic, persistent changes you may want to also update /etc/wireguard/<iface>.conf.
  This tool can append a [Peer] block with --persist-server-conf (optional).
"""

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple, List
import logging
from .settings import SETTINGS

# ----------------------------
# Helpers
# ----------------------------

def run(cmd: List[str], check=True, capture_output=True, text=True, input=None) -> subprocess.CompletedProcess:
    """Run a command and return the CompletedProcess. Raises if check=True and nonzero exit."""
    logging.log(logging.DEBUG, f"{' '.join(cmd)}")
    if SETTINGS.getboolean("Debug", "dry_run"):
        logging.log(logging.INFO, f"dry run: {' '.join(cmd)}")
        return subprocess.CompletedProcess(args=[], returncode=0)
    return subprocess.run(cmd, check=check, capture_output=capture_output, text=text, input=input)

def which(bin_name: str) -> Optional[str]:
    from shutil import which as _which
    return _which(bin_name)

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def require_binary(bin_name: str):
    if which(bin_name) is None:
        eprint(f"Error: required binary '{bin_name}' not found in PATH.")
        sys.exit(1)

def read_server_public_key(interface: str) -> str:
    """Read server's public key from running interface (preferred)."""
    cp = run(["wg", "show", interface, "public-key"])
    return cp.stdout.strip()

def read_server_conf_path(interface: str) -> Path:
    return Path("/etc/wireguard") / f"{interface}.conf"

def parse_endpoint_from_conf(conf_path: Path) -> Optional[str]:
    """Best-effort parse of Endpoint from an existing [Peer] that looks like 'server' or from [Interface] with ListenPort + external host unknown."""
    if not conf_path.exists():
        return None
    host_port = None
    with conf_path.open() as f:
        for line in f:
            line = line.strip()
            if line.lower().startswith("endpoint"):
                # Endpoint = host:port
                _, val = line.split("=", 1)
                host_port = val.strip()
                break
    return host_port

def parse_listen_port_from_conf(conf_path: Path) -> Optional[str]:
    if not conf_path.exists():
        return None
    with conf_path.open() as f:
        for line in f:
            line = line.strip()
            if line.lower().startswith("listenport"):
                _, val = line.split("=", 1)
                return val.strip()
    return None

def genkeypair() -> Tuple[str, str]:
    """Return (private_key, public_key) using `wg`."""
    r = run(["wg", "genkey"])
    logging.log(logging.DEBUG, r)
    priv = r.stdout.strip()
    cp = run(["wg", "pubkey"], input=priv)
    pub = cp.stdout.strip()
    return priv, pub

def gen_psk() -> str:
    return run(["wg", "genpsk"]).stdout.strip()

def optional_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Must be an integer")


# ----------------------------
# Core operations
# ----------------------------

def create_client_config(
    interface: str,
    name: str,
    address: str,
    dns: Optional[str],
    endpoint: Optional[str],
    allowed_ips_peer: str,
    preshared: bool,
    persistent_keepalive: Optional[int],
    out_dir: Path,
    persist_server_conf: bool,
) -> Path:
    """
    Create a client config .conf (and optionally append to server conf).
    Returns path to the generated client config.
    """
    require_binary("wg")

    server_conf = read_server_conf_path(interface)
    # Try to discover server public key from the running interface first
    try:
        server_pub = read_server_public_key(interface)
    except subprocess.CalledProcessError:
        # Fallback: try to read PublicKey from a [Peer] block in conf (not typical)
        eprint(f"Warning: could not read running public key for {interface}. Is the interface up?")
        server_pub = None

    # If endpoint not provided, try to pull from conf (best effort)
    if endpoint is None:
        endpoint = parse_endpoint_from_conf(server_conf)
        if endpoint is None:
            lp = parse_listen_port_from_conf(server_conf)
            if lp:
                eprint(f"Note: No Endpoint found. You supplied a ListenPort={lp}, but client needs a routable endpoint host:port.")
            eprint("Tip: Provide --endpoint host:port for a complete client config.")

    # Generate client keys (and PSK)
    cli_priv, cli_pub = genkeypair()
    psk = gen_psk() if preshared else None

    # Build client file content
    lines = []
    lines.append("[Interface]")
    lines.append(f"PrivateKey = {cli_priv}")
    lines.append(f"Address = {address}")
    if dns:
        lines.append(f"DNS = {dns}")
    lines.append("")  # blank
    lines.append("[Peer]")

    if server_pub:
        lines.append(f"PublicKey = {server_pub}")
    else:
        lines.append("# PublicKey = <server-public-key>  # Could not detect; fill in")

    if psk:
        lines.append(f"PresharedKey = {psk}")

    lines.append(f"AllowedIPs = {allowed_ips_peer}")
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    if persistent_keepalive is not None:
        lines.append(f"PersistentKeepalive = {persistent_keepalive}")
    lines.append("")  # end

    out_dir.mkdir(parents=True, exist_ok=True)
    client_conf_path = out_dir / f"{name}.conf"
    client_conf_path.write_text("\n".join(lines) + "\n")

    print(f"Created client config: {client_conf_path}")

    # Print pubkey for server-side add
    print(f"Client public key: {cli_pub}")
    if psk:
        print(f"Preshared key: {psk}")

    # Optionally append to server .conf for persistence
    if persist_server_conf:
        blk = []
        blk.append("[Peer]")
        blk.append(f"# {name}")
        blk.append(f"PublicKey = {cli_pub}")
        if psk:
            blk.append(f"PresharedKey = {psk}")
        blk.append(f"AllowedIPs = {address}")
        if persistent_keepalive is not None:
            blk.append(f"PersistentKeepalive = {persistent_keepalive}")
        blk.append("")
        server_conf.parent.mkdir(parents=True, exist_ok=True)
        with server_conf.open("a") as f:
            f.write("\n".join(blk) + "\n")
        print(f"Appended peer to server config: {server_conf} (remember to `wg-quick down {interface} && wg-quick up {interface}` or reload)")

    # Optional QR output (if qrencode available)
    if which("qrencode") is not None:
        # Print QR to stdout (terminal), and also store a PNG file next to the conf
        try:
            cfg = client_conf_path.read_text()
            print("\nQR (for mobile clients):")
            subprocess.run(["qrencode", "-t", "ANSIUTF8"], input=cfg, text=True)
            png_path = client_conf_path.with_suffix(".png")
            subprocess.run(["qrencode", "-o", str(png_path)], input=cfg, text=True, check=True)
            print(f"Saved QR PNG: {png_path}")
        except Exception as ex:
            eprint(f"Note: qrencode failed: {ex}")

    return client_conf_path

import tempfile, pathlib

def add_peer(
    interface: str,
    peer_pubkey: str,
    allowed_ips: str,
    preshared_key: Optional[str],
    persistent_keepalive: Optional[int],
):
    """Add peer live to interface using `wg set`."""
    require_binary("wg")

    tf = tempfile.NamedTemporaryFile(delete=False)

    cmd = ["wg", "set", interface, "peer", peer_pubkey]
    if preshared_key:    
        tf.write(preshared_key.encode('utf-8'))
        cmd += ["preshared-key", f"{str(tf.name)}"]
    cmd += ["allowed-ips", allowed_ips]
    if persistent_keepalive is not None:
        cmd += ["persistent-keepalive", str(persistent_keepalive)]

    tf.flush()

    run(cmd, check=True, capture_output=False, text=True).check_returncode()
    
    tf.close()
    os.unlink(tf.name)

    logging.log(logging.INFO, f"Added peer {peer_pubkey[:16]}… to {interface} with AllowedIPs {allowed_ips}")

def remove_peer(interface: str, peer_pubkey: str):
    """Remove peer live from interface using `wg set <iface> peer <pubkey> remove`."""
    require_binary("wg")
    run(["wg", "set", interface, "peer", peer_pubkey, "remove"], check=True, capture_output=False, text=True)
    logging.log(logging.INFO, f"Removed peer {peer_pubkey[:16]}… from {interface}")

def get_current_peers_pubkeys(interface: str) -> set[str]:
    """
    Return set of public keys currently configured on the interface.
    Works with: wg show <iface> peers
    """
    try:
        out = run(["wg", "show", interface, "peers"]).stdout.strip()
        if not out:
            return set()
        return set([line.strip() for line in out.splitlines() if line.strip()])
    except subprocess.CalledProcessError as ex:
        raise SystemExit(f"wg show failed for {interface}: {ex.stderr or ex}")

def get_allowed_ips(interface: str, with_slash=False) -> Dict[str, str]:
    """
    Return set of public keys currently configured on the interface.
    Works with: wg show <iface> endpoints
    """
    # pubkeys = []
    # try:
    #     out = run(["wg", "show", interface, "peers"]).stdout.strip()
    #     pubkeys += set([line.strip() for line in out.splitlines() if line.strip()])
    # except subprocess.CalledProcessError as ex:
    #     raise SystemExit(f"wg show failed for {interface}: {ex.stderr or ex}")
    # TODO: handl logic here to fetch client ip from the device
    try:
        out = run(["wg", "show", interface, "allowed-ips"]).stdout.strip()
        pubkeyEndpointPairs = [line.strip().split("\t", 2) for line in out.splitlines() if line.strip()]
        if with_slash:
            result = dict((entry[0], entry[1]) for entry in pubkeyEndpointPairs)
        else:
            result = dict((entry[0], entry[1].split("/", 2)[0]) for entry in pubkeyEndpointPairs)
        return result
        
    except subprocess.CalledProcessError as ex:
        raise SystemExit(f"wg show failed for {interface}: {ex.stderr or ex}")

def get_current_peers(interface: str) -> Dict[str, str | None]:
    """
    Return set of public keys currently configured on the interface.
    Works with: wg show <iface> endpoints
    """
    # pubkeys = []
    # try:
    #     out = run(["wg", "show", interface, "peers"]).stdout.strip()
    #     pubkeys += set([line.strip() for line in out.splitlines() if line.strip()])
    # except subprocess.CalledProcessError as ex:
    #     raise SystemExit(f"wg show failed for {interface}: {ex.stderr or ex}")
    # TODO: handl logic here to fetch client ip from the device
    try:
        out = run(["wg", "show", interface, "endpoints"]).stdout.strip()
        pubkeyEndpointPairs = [line.strip().split("\t", 2) for line in out.splitlines() if line.strip()]
        result = dict((entry[0], entry[1] if entry[1] != "(none)" else None) for entry in pubkeyEndpointPairs)
        return result
        
    except subprocess.CalledProcessError as ex:
        raise SystemExit(f"wg show failed for {interface}: {ex.stderr or ex}")
        
def clear_peers(interface: str):
    for pubkey in get_current_peers(interface=interface):
        logging.log(logging.DEBUG, f"clearing peer: {pubkey}")
        remove_peer(interface=interface, peer_pubkey=pubkey)

def remove_peer_if_exists(interface: str, peer_pubkey: str):
    peers = get_current_peers(interface=interface)
    if peer_pubkey in peers:
        remove_peer(interface=interface, peer_pubkey=peer_pubkey)

# ----------------------------
# CLI
# ----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="WireGuard peer manager using `wg`.")
    sub = p.add_subparsers(dest="cmd", required=True)

    # create-config
    sc = sub.add_parser("create-config", help="Generate keys and a client config file for a new peer")
    sc.add_argument("interface", help="WireGuard interface, e.g., wg0")
    sc.add_argument("name", help="Peer name (used for output filename and server comment)")
    sc.add_argument("--address", required=True, help="Client interface Address (e.g., 10.0.0.2/32 or fd00::2/128)")
    sc.add_argument("--dns", help="Comma-separated DNS servers for client (optional)")
    sc.add_argument("--endpoint", help="Server endpoint host:port (if omitted, best-effort read from server conf)")
    sc.add_argument("--allowed-ips-peer", default="0.0.0.0/0, ::/0", help="AllowedIPs in the client's [Peer] block (default: 0.0.0.0/0, ::/0)")
    sc.add_argument("--no-psk", action="store_true", help="Do not use a preshared key")
    sc.add_argument("--persistent-keepalive", type=optional_int, help="Seconds, e.g., 25 (optional)")
    sc.add_argument("--out", type=Path, default=Path("./"), help="Output directory for the client .conf (default: current dir)")
    sc.add_argument("--persist-server-conf", action="store_true", help="Append a [Peer] block to /etc/wireguard/<iface>.conf")

    # add-peer
    sa = sub.add_parser("add-peer", help="Add a peer to a running interface")
    sa.add_argument("interface", help="WireGuard interface, e.g., wg0")
    sa.add_argument("public_key", help="Peer public key (Base64)")
    sa.add_argument("--allowed-ips", required=True, help="Comma-separated AllowedIPs to route to this peer (e.g., 10.0.0.2/32)")
    sa.add_argument("--preshared-key", help="Optional PSK (Base64) to use with this peer")
    sa.add_argument("--persistent-keepalive", type=optional_int, help="Seconds, e.g., 25 (optional)")

    # remove-peer
    sr = sub.add_parser("remove-peer", help="Remove a peer from a running interface")
    sr.add_argument("interface", help="WireGuard interface, e.g., wg0")
    sr.add_argument("public_key", help="Peer public key (Base64) to remove")

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "create-config":
        create_client_config(
            interface=args.interface,
            name=args.name,
            address=args.address,
            dns=args.dns,
            endpoint=args.endpoint,
            allowed_ips_peer=args.allowed_ips_peer,
            preshared=not args.no_psk,
            persistent_keepalive=args.persistent_keepalive,
            out_dir=args.out,
            persist_server_conf=args.persist_server_conf,
        )

    elif args.cmd == "add-peer":
        add_peer(
            interface=args.interface,
            peer_pubkey=args.public_key,
            allowed_ips=args.allowed_ips,
            preshared_key=args.preshared_key,
            persistent_keepalive=args.persistent_keepalive,
        )

    elif args.cmd == "remove-peer":
        remove_peer(
            interface=args.interface,
            peer_pubkey=args.public_key,
        )

if __name__ == "__main__":
    main()
