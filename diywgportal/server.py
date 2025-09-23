#!/usr/bin/env python3
"""
yubi_portal.py — Minimal YubiKey OTP -> WireGuard portal (standard library only)

Flow:
  1) User opens page, pastes YubiKey OTP, chooses a display name (optional).
  2) Server verifies OTP with Yubico (wsapi/2.0/verify) using your CLIENT_ID (+ optional HMAC secret).
  3) If valid:
       - Auto-allocate next free /32 from ADDRESS_POOL_V4
       - Generate client keypair (+ PSK if enabled)
       - Build client .conf (with DNS/Endpoint/Keepalive)
       - Add peer live (wg.add_peer)
       - Insert peer row into SQLite (peers.add_peer)
       - Return a results page with the config in a textarea + a "Download" link
  4) If invalid: show error.

Requirements:
  - Place this next to wg.py and peers.py (so we can `import wg, peers`)
  - Run as root (or with privileges) because we call `wg` underneath
  - Set env var YUBICO_CLIENT_ID, and optionally YUBICO_SECRET_KEY (Base64 of raw key) for HMAC verify

Security notes:
  - This is a minimal, single-process demo. For production: add HTTPS/TLS termination,
    rate limiting, CSRF protection, logging, stricter input validation, and a proper template engine.
"""

from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging
import traceback
from typing import Dict, Tuple
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import urlopen, Request
import urllib.error
import ssl
import os
import hmac
import base64
import hashlib
import secrets
import time
import ipaddress
import sqlite3
from pathlib import Path
from html import escape

from diywgportal.accounts import fetch_accounts
from diywgportal.management import sync_db_to_wg

# Local modules from earlier answers
from . import wg
from . import peers
from .settings import SETTINGS

# ------------------
# Configuration
# ------------------

# WireGuard server/interface settings
HTML_TITLE = os.environ.get("PORTAL_TITLE", "VPN Access Portal")

# Simple in-memory cache for one-click download (token -> config text)
DOWNLOAD_CACHE: Dict[str, Tuple["SimpleWGConfiguration", int]] = {}  # token -> (conf_text, expires_at_epoch)

# ------------------
# Helpers
# ------------------

def now() -> int:
    return int(time.time())

def cleanup_cache():
    t = now()
    expired = [k for k, (_, exp) in DOWNLOAD_CACHE.items() if exp < t]
    for k in expired:
        DOWNLOAD_CACHE.pop(k, None)

def sign_yubico_params(params: dict, secret_b64: str) -> str:
    """
    HMAC-SHA1 sign Yubico request (or response) per spec.
    For requests: sign over key=value pairs sorted by key, joined with '&', then Base64 result (no padding changes).
    """
    key = base64.b64decode(secret_b64)
    # Build message: key=value sorted by key, '&'-joined; do not include 'h'
    items = [(k, v) for k, v in params.items() if k != "h"]
    items.sort(key=lambda kv: kv[0])
    msg = "&".join(f"{k}={v}" for k, v in items).encode("utf-8")
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    return base64.b64encode(mac).decode("ascii")

def parse_kv_body(body: str) -> dict:
    """
    Yubico returns newline-separated key=value lines.
    """
    out = {}
    for line in body.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out

def verify_yubikey_otp(otp: str) -> tuple[bool, str, str]:
    """
    Verify OTP with Yubico. Returns (ok, public_id, error_message)
    public_id is the modhex prefix (first 12+ chars) of the OTP.
    """
    if not SETTINGS.get("Yubikey", "yubico_client_id"):
        return False, "", "Server not configured: missing YUBICO_CLIENT_ID"

    otp = otp.strip()
    if not otp or len(otp) < 32 or len(otp) > 48:
        return False, "", "Invalid OTP format"

    nonce = secrets.token_hex(16)
    params = {
        "id": SETTINGS.get("Yubikey", "yubico_client_id"),
        "otp": otp,
        "nonce": nonce,
    }

    # Optional request HMAC
    if SETTINGS.get("Yubikey", "YUBICO_SECRET_KEY_B64"):
        params["h"] = sign_yubico_params(params, SETTINGS.get("Yubikey", "YUBICO_SECRET_KEY_B64"))

    qs = urlencode(params)
    url = f'{SETTINGS.get("Yubikey", "yubico_verify_url")}?{qs}'

    # TLS request (default context is fine)
    try:
        with urlopen(Request(url, method="GET"), context=ssl.create_default_context(), timeout=10) as resp:
            data = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as ex:
        return False, "", f"Network error contacting Yubico: {ex}"

    parsed = parse_kv_body(data)
    # Basic checks
    if parsed.get("nonce") != nonce:
        return False, "", "Nonce mismatch in Yubico response"
    if parsed.get("otp") != otp:
        return False, "", "OTP mismatch in Yubico response"

    # Optional response HMAC validation
    if SETTINGS.get("Yubikey", "YUBICO_SECRET_KEY_B64"):
        received_h = parsed.get("h", "")
        calc = sign_yubico_params(parsed, SETTINGS.get("Yubikey", "YUBICO_SECRET_KEY_B64"))
        if not hmac.compare_digest(received_h, calc):
            return False, "", "Invalid HMAC signature from Yubico"

    status = parsed.get("status", "")
    if status != "OK":
        return False, "", f"Yubico status: {status or 'UNKNOWN'}"

    # Extract public id (OTP prefix up to the last 32 chars of ciphertext).
    # A common heuristic is: public_id = otp[:-32]
    public_id = otp[:-32]
    if not public_id:
        public_id = otp[:12]  # fallback to first 12 chars
    return True, public_id, ""

def ip_alloc_next_free_v4(conn: sqlite3.Connection, interface: str, pool_cidr: str) -> str:
    """
    Find first free host IP in pool_cidr not present as 'allowed_ips' in peers table.
    Returns 'X.X.X.X/32'.
    """
    net = ipaddress.ip_network(pool_cidr, strict=False)
    # Gather used IPs from DB
    rows = conn.execute(
        "SELECT allowed_ips FROM peers WHERE interface=?", (interface,)
    ).fetchall()
    used = set()
    for (cidr,) in rows:
        # allowed_ips might be "10.0.0.2/32" or "10.0.0.2/32, 10.0.0.3/32"
        for part in str(cidr).split(","):
            part = part.strip()
            if not part:
                continue
            try:
                ipif = ipaddress.ip_interface(part)
                used.add(str(ipif.ip))
            except ValueError:
                continue

    # iterate hosts; skip network address and (optionally) first couple addresses
    # We'll start from .2 to leave .1 potentially for the server (convention)
    # hosts = list(net.hosts())
    for index, ip in enumerate(net.hosts()):
        # skip .1 as server common choice
        if index < min(1, SETTINGS.getint("General", "RESERVED_ADDRESS_COUNT")):
            continue
        if str(ip) not in used:
            return f"{ip}/32"

    raise RuntimeError("Address pool exhausted")

def build_client_conf(
    client_priv: str,
    client_address: str,
    server_pub: str,
    endpoint: str,
    dns: str | None,
    allowed_ips_peer: str,
    keepalive: int | None,
) -> str:
    lines = []
    lines.append("[Interface]")
    lines.append(f"PrivateKey = {client_priv}")
    lines.append(f"Address = {client_address}")
    if dns:
        lines.append(f"DNS = {dns}")
    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_pub}")
    lines.append(f"AllowedIPs = {allowed_ips_peer}")
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    if keepalive is not None:
        lines.append(f"PersistentKeepalive = {keepalive}")
    lines.append("")
    return "\n".join(lines) + "\n"

def html_page(body: str, status: int = 200) -> bytes:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(HTML_TITLE)}</title>
<style>
  :root {{
    --bg: #0f172a;
    --card: #111827;
    --fg: #e5e7eb;
    --muted: #9ca3af;
    --accent: #22c55e;
    --danger: #ef4444;
  }}
  body {{
    margin: 0; background: radial-gradient(1200px 600px at 10% -10%, #1f2937 0, var(--bg) 60%);
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
    color: var(--fg);
  }}
  .wrap {{ max-width: 720px; margin: 8vh auto; padding: 0 16px; }}
  .card {{
    background: linear-gradient(180deg, #0b0f1a, var(--card));
    border: 1px solid #1f2937; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,.4);
    padding: 28px;
  }}
  h1 {{ margin: 0 0 8px; font-size: 24px; letter-spacing: .2px; }}
  p.muted {{ color: var(--muted); margin-top: 0 }}
  form {{
    display: grid; gap: 14px; margin-top: 18px;
  }}
  label {{ font-size: 14px; color: var(--muted); }}
  input[type=text] {{
    width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid #263244;
    background: #0b1220; color: var(--fg); outline: none;
  }}
  button {{
    background: var(--accent); color: #06240f; font-weight: 700;
    padding: 12px 16px; border: 0; border-radius: 10px; cursor: pointer;
  }}
  .error {{ background: #2a0d0f; border: 1px solid #5b1b21; color: #ffb4b4; padding: 10px 12px; border-radius: 10px; }}
  textarea {{
    width: 100%; height: 240px; padding: 12px 14px; border-radius: 10px; border: 1px solid #263244;
    background: #0b1220; color: var(--fg); resize: vertical;
  }}
  .row {{ display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }}
  a.btn {{ display: inline-block; text-decoration: none; background: #1f2937; border: 1px solid #2b3649; padding: 10px 12px; border-radius: 10px; color: var(--fg); }}
  .kv {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0b1220; display: inline-block; padding: 2px 6px; border-radius: 6px; border:1px solid #263244; }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      {body}
    </div>
  </div>
</body>
</html>""".encode("utf-8")

def render_form(error: str = "") -> bytes:
    err = f'<div class="error">{escape(error)}</div>' if error else ""
    body = f"""
<h1>{escape(HTML_TITLE)}</h1>
<p class="muted">Tap your YubiKey to generate a one-time password and press “Get VPN”.</p>
{err}
<form method="POST" action="/">
  <div>
    <label for="otp">YubiKey OTP</label><br/>
    <input type="text" id="otp" name="otp" autofocus="autofocus" placeholder="cccccc...djgkktfgrh" required>
  </div>
  <div style="display: none;">
    <label for="name">Display name (optional)</label><br/>
    <input type="text" id="name" name="name" placeholder="alice-laptop">
  </div>
  <div class="row">
    <button type="submit">Get VPN</button>
    <a class="btn" href="/healthz">Health check</a>
  </div>
</form>
"""
    return html_page(body)



@dataclass
class SimpleWGConfiguration:
    interface: str
    private_key: str
    public_key: str
    address: str
    peer_public_key: str
    peer_preshared_key: str
    peer_allowed_ips: str
    peer_endpoint: str
    peer_persistent_keepalive: str # =int(SETTINGS.get("Peers", "keep_alive_seconds")) if SETTINGS.getboolean("Peers", "configure_keep_alive") else None,

    def to_query_url(self):
        parts = []
        parts.append(f"interface={self.interface}")
        parts.append(f"private_key={self.private_key}")
        parts.append(f"address={self.address}")
        parts.append(f"peer_public_key={self.peer_public_key}")
        parts.append(f"peer_preshared_key={self.peer_preshared_key}")
        parts.append(f"peer_allowed_ips={self.peer_allowed_ips}")
        parts.append(f"peer_endpoint={self.peer_endpoint}")
        parts.append(f"peer_persistent_keepalive={self.peer_persistent_keepalive}")
        parts.append(f"raw={base64.urlsafe_b64encode(self.to_string().encode('utf-8')).decode('ascii')}")
        return f'?{"&".join(parts)}'

    def to_string(self):
        return f"""# Interface: {self.interface} Preshared Key: {self.peer_preshared_key}
[Interface]
PrivateKey = {self.private_key}
Address = {self.address}
# PublicKey = {self.public_key}

[Peer]
PublicKey = {self.peer_public_key}
AllowedIPs = {self.peer_allowed_ips}
Endpoint = {self.peer_endpoint}
PersistentKeepAlive = {self.peer_persistent_keepalive}
# For the future:
PresharedKey = {self.peer_preshared_key}

"""


import base64
def make_wireguard_url(conf: SimpleWGConfiguration):
    return f'<a class="btn" href="wireguard://WireGuard.local/SetConfiguration{conf.to_query_url()}">Install</a>'


def render_result(conf: SimpleWGConfiguration, token: str) -> bytes:
    safe_conf = escape(conf.to_string())
    dn_link = f"/download?token={escape(token)}"
    body = f"""
<h1>Configuration ready</h1>
<p class="muted">Copy the configuration below into your WireGuard client, or download the file.</p>
<div class="row" style="margin:10px 0 16px;">
  <span>Assigned IP: <span class="kv">{escape(conf.address)}</span></span>
  <span>Public key: <span class="kv">{escape(conf.public_key[:16])}…</span></span>
</div>
<div class="row">
  <textarea readonly>{safe_conf}</textarea>
</div>
<div class="row" style="margin-top:12px;">
  <a class="btn" href="/">Back</a>
  {make_wireguard_url(conf)}
  <a class="btn" href="{dn_link}">Download .conf</a>
</div>
"""
    return html_page(body)

def make_download_token(conf: SimpleWGConfiguration) -> str:
    token = secrets.token_urlsafe(24)
    DOWNLOAD_CACHE[token] = (conf, now() + int(SETTINGS.get("Server", "download_ttl")))
    cleanup_cache()
    return token

# ------------------
# HTTP handler
# ------------------

class Portal(BaseHTTPRequestHandler):
    def do_GET(self):
        print(self.client_address)
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._ok(render_form())
            return
        if parsed.path == "/healthz":
            ok = bool(SETTINGS.get("Yubikey", "yubico_client_id")) and Path(SETTINGS.get("Peers", "database_path")).exists()
            status = 200 if ok else 500
            msg = f'ok: yubico_id={"set" if SETTINGS.get("Yubikey", "yubico_client_id") else "missing"}, db={"present" if Path(SETTINGS.get("Peers", "database_path")).exists() else "missing"}\n'
            self._raw(status, b"text/plain; charset=utf-8", msg.encode("utf-8"))
            return
        if parsed.path == "/download":
            qs = parse_qs(parsed.query or "")
            token = (qs.get("token") or [""])[0]
            conf = self._pop_conf(token)
            if not conf:
                self._raw(404, b"text/plain; charset=utf-8", b"Invalid or expired token\n")
                return
            conf_text = conf.to_string()
            fname = f"{conf.interface}.conf"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
            self.send_header("Content-Length", str(len(conf_text.encode("utf-8"))))
            self.end_headers()
            self.wfile.write(conf_text.encode("utf-8"))
            return

        self._raw(404, b"text/plain; charset=utf-8", b"Not found\n")

    def do_POST(self):
        if self.path != "/":
            self._raw(404, b"text/plain; charset=utf-8", b"Not found\n")
            return
        
        # TODO: register client_ip so the endpoint can only be that
        # and of course make the watch dog check against this!
        client_ip, client_port = self.client_address

        # parse form
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(body)
        otp = (form.get("otp") or [""])[0].strip()
        # name_in = (form.get("name") or [""])[0].strip()

        # check otp against registered accounts
        accounts = fetch_accounts(interface=SETTINGS.get("General", "interface"))
        matches = [acc for acc in accounts if acc.public_id == otp[:12]]
        if len(matches) == 0:
            self._ok(render_form(error=f"user not registered: {otp[:12]}"))
            return
        
        account = matches[0]

        # verify yubikey OTP
        ok, pub_id, err = verify_yubikey_otp(otp)
        if not ok:
            self._ok(render_form(error=err))
            return
        if pub_id != account.public_id:
            self._ok(render_form(error=f"user login failed: {otp[:12]}"))
            return

        # derive a sane name (allow a-z0-9- only)
        # base_name = name_in if name_in else f"user-{pub_id}"
        # safe_name = "".join(c for c in base_name.lower() if c.isalnum() or c == "-")[:48] or f"user-{pub_id}"
        # safe_name = pub_id

        try:
            # Open DB, ensure schema
            conn = peers.connect(Path(SETTINGS.get("Peers", "database_path")))
            peers.init_db(conn)

            # Allocate IP
            assigned = ip_alloc_next_free_v4(conn, SETTINGS.get("General", "interface"), SETTINGS.get("General", "address_pool_v4"))

            # Generate client keys (+ optional PSK)
            cli_priv, cli_pub = wg.genkeypair()
            psk = wg.gen_psk() if SETTINGS.getboolean("Peers", "configure_preshared_key") else ""

            # Server public key
            try:
                server_pub = wg.read_server_public_key(SETTINGS.get("General", "interface"))
            except Exception:
                # If interface not up, we still generate client config with placeholder key
                server_pub = "<server-public-key>"

            conf = SimpleWGConfiguration(interface=SETTINGS.get("Peers", "interface_name"),
                                         private_key=cli_priv,
                                         address=assigned,
                                         public_key=cli_pub,
                                         peer_public_key=server_pub,
                                         peer_endpoint=SETTINGS.get("General", "endpoint"),
                                         peer_preshared_key=psk,
                                         peer_allowed_ips=SETTINGS.get("Peers", "allowed_ips"),
                                         peer_persistent_keepalive=SETTINGS.get("Peers", "keep_alive_seconds") if SETTINGS.getboolean("Peers", "configure_keep_alive") else "")
            # Build client config (client side)
            conf_text = conf.to_string()

            # Add peer LIVE on server (AllowedIPs = client's /32)
            try:
                wg.remove_peer_if_exists(interface=SETTINGS.get("General", "interface"), peer_pubkey=cli_pub)
                wg.add_peer(
                    interface=SETTINGS.get("General", "interface"),
                    peer_pubkey=cli_pub,
                    allowed_ips=assigned,
                    preshared_key=psk,
                    persistent_keepalive=int(SETTINGS.get("Peers", "keep_alive_seconds")) if SETTINGS.getboolean("Peers", "configure_keep_alive") else None,
                )
            except Exception as ex:
                # Non-fatal for delivering a config, but warn
                conf_text = conf_text + f"# NOTE: Failed to add peer live: {ex}\n"

            # Persist to DB
            peers.update_or_insert_peer(
                conn,
                interface=SETTINGS.get("General", "interface"),
                name=pub_id,
                public_key=cli_pub,
                preshared_key=psk,
                allowed_ips=assigned,
                persistent_keepalive=int(SETTINGS.get("Peers", "keep_alive_seconds")) if SETTINGS.getboolean("Peers", "configure_keep_alive") else None,
                enabled=True,
                client_ip=client_ip,
            )

            # Optional: also append to /etc/wireguard/<iface>.conf for persistence
            # (We won't touch the file here—admin can run apply_peers.py or wg-quick restart.)

            # Serve result
            token = make_download_token(conf)
            self._ok(render_result(conf, token))

        except Exception as ex:
            logging.log(logging.ERROR, traceback.format_exc())
            self._ok(render_form(error=f"Server error: {ex}"))

    # ---------------- helpers ----------------
    def _ok(self, content: bytes):
        self._raw(200, b"text/html; charset=utf-8", content)

    def _raw(self, code: int, ctype: bytes, content: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype.decode("ascii"))
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _pop_conf(self, token: str) -> SimpleWGConfiguration | None:
        cleanup_cache()
        val = DOWNLOAD_CACHE.pop(token, None)
        if not val:
            return None
        conf, _ = val
        return conf

# ------------------
# Main
# ------------------

def main(conn: sqlite3.Connection, interface: str):
    # Ensure wg binary
    wg.require_binary("wg")

    port = SETTINGS.getint("Server", "BIND_PORT")
    host = SETTINGS.get("Server", "BIND_ADDRESS")

    httpd = HTTPServer((host, port), Portal)
    httpd.timeout = SETTINGS.getint("Watchdog", "watch_interval_seconds")
    print(f"[yubi_portal] listening on http://{host}:{port}  (interface={interface}, pool={SETTINGS.get('General', 'address_pool_v4')})")
    if not SETTINGS.get("Yubikey", "yubico_client_id"):
        print("[yubi_portal] WARNING: YUBICO_CLIENT_ID not set")
    if SETTINGS.get("Yubikey", "YUBICO_SECRET_KEY_B64"):
        print("[yubi_portal] HMAC verification: enabled")
    else:
        print("[yubi_portal] HMAC verification: DISABLED (set YUBICO_SECRET_KEY to enable)")

    last_watchdog = 0.0
    try:
        while True:
            # handle exactly one request, or return after timeout
            httpd.handle_request()  # internally does select/poll with httpd.timeout

            # if we timed out (i.e., no request), run watchdog tick
            t = time.monotonic()
            if t - last_watchdog >= SETTINGS.getint("Watchdog", "watch_interval_seconds"):
                try:
                    logging.log(logging.DEBUG, f"watchdog: syncing db to wg")
                    sync_db_to_wg(conn, interface)
                except Exception as ex:
                    print(f"[watchdog] ERROR: {ex}")
                last_watchdog = t
            else:
                logging.log(logging.DEBUG, f"waiting for watchdog cycle")
    except KeyboardInterrupt:
        print("\n[portal] shutting down…")
