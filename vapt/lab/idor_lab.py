#!/usr/bin/env python3
"""
VAPT practice lab — deliberately-vulnerable account / orders app (Area 2: IDOR).

PURPOSE
    A safe, local, offline target for the access-control (IDOR / broken object-level
    authorization) test cases in ../02-playbook.md, WITHOUT touching the real store.
    Real session cookies are used, so you prove each flaw the proper way:
    log in as one user, keep YOUR session, and reach ANOTHER user's object by
    changing an id.

RUN
    python3 idor_lab.py            # http://127.0.0.1:8001
    python3 idor_lab.py 8088       # custom port

SAFETY
    - 127.0.0.1 only. In-memory, no real data, no external calls. Ctrl-C to stop.
    - VULNERABLE-BY-DESIGN teaching target. Do NOT deploy it anywhere.

Seeded accounts:
    alice@example.com / alicepw   -> customer 1001, orders 5001 & 5003
    bob@example.com   / bobpw     -> customer 1002, orders 5002 & 5004

The flaws (all labelled "# FLAW 2.x" below) map to the playbook:
    2.1 Orders IDOR            -> /orders/<id> returns any order, no ownership check
    2.2 Account/profile IDOR   -> /account?id=<n> views/edits any profile
    2.3 Custom-app endpoint    -> /api/order returns data with NO session at all
    2.4 Forced browsing        -> /apps/rewards/admin has no role check
"""
import sys
import html
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse
import json as _json

# ---------------------------------------------------------------------------
# In-memory data
# ---------------------------------------------------------------------------
CUSTOMERS = {
    1001: {"email": "alice@example.com", "password": "alicepw",
           "name": "Alice Anderson", "address": "1 Rose Ln", "phone": "555-0101"},
    1002: {"email": "bob@example.com", "password": "bobpw",
           "name": "Bob Brown", "address": "2 Oak St", "phone": "555-0202"},
}
EMAIL_TO_ID = {c["email"]: cid for cid, c in CUSTOMERS.items()}

ORDERS = {
    5001: {"customer": 1001, "total": "£42.00", "items": "Blue Mug x2", "card_last4": "4242"},
    5002: {"customer": 1002, "total": "£17.50", "items": "Notebook x1", "card_last4": "1881"},
    5003: {"customer": 1001, "total": "£99.99", "items": "Headphones x1", "card_last4": "4242"},
    5004: {"customer": 1002, "total": "£8.00", "items": "Stickers x4", "card_last4": "1881"},
}

SESSIONS = {}  # session_token -> customer_id


# ---------------------------------------------------------------------------
# HTML shell
# ---------------------------------------------------------------------------
BANNER = ("<div style='background:#7a1f1f;color:#fff;padding:8px 12px;font:14px system-ui'>"
          "⚠ VULNERABLE-BY-DESIGN practice lab — localhost only. Not a real system.</div>")
CSS = """<style>
 body{font:16px system-ui;margin:0;background:#0f1115;color:#e6e6e6}
 .wrap{max-width:620px;margin:32px auto;padding:0 16px}
 .card{background:#181b22;border:1px solid #2a2f3a;border-radius:10px;padding:18px;margin:14px 0}
 h1{font-size:20px;margin:0 0 10px} h2{font-size:15px;color:#9aa4b2;margin:0 0 10px}
 label{display:block;margin:8px 0 4px;color:#c3cad6;font-size:14px}
 input{width:100%;box-sizing:border-box;padding:9px;border-radius:8px;border:1px solid #2a2f3a;background:#0f1115;color:#e6e6e6}
 button{margin-top:12px;padding:10px 16px;border:0;border-radius:8px;background:#3b82f6;color:#fff;cursor:pointer}
 a{color:#60a5fa} nav a{margin-right:14px} table{width:100%;border-collapse:collapse;font-size:14px}
 td,th{border-bottom:1px solid #2a2f3a;padding:6px 8px;text-align:left}
 .msg{padding:9px 12px;border-radius:8px;margin:10px 0;font-size:14px}
 .ok{background:#14361f;color:#8ef0ab;border:1px solid #1f5a33}
 .err{background:#3a1420;color:#ffb3c4;border:1px solid #5a1f33}
 .note{color:#8b93a1;font-size:12px} code{background:#11141a;padding:1px 5px;border-radius:5px}
</style>"""


def shell(body, me=None):
    who = f"Signed in as <b>{html.escape(me['email'])}</b> (customer {me_id(me)})" if me else "Not signed in"
    nav = ("<nav><a href='/'>Home</a><a href='/account'>My account</a>"
           "<a href='/orders'>My orders</a><a href='/apps/rewards/admin'>Rewards admin</a>"
           "<a href='/logout'>Logout</a></nav>")
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>VAPT IDOR Lab</title>{CSS}</head><body>{BANNER}<div class='wrap'>"
            f"<p class='note'>{who}</p>{nav}{body}"
            f"<p class='note'>Seeded: alice@example.com/alicepw (cust 1001) · bob@example.com/bobpw (cust 1002)</p>"
            f"</div></body></html>").encode()


def me_id(me):
    return EMAIL_TO_ID.get(me["email"]) if me else None


def msg(t, ok=True):
    return f"<div class='msg {'ok' if ok else 'err'}'>{html.escape(t)}</div>"


# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "VAPTLab/1.0"

    # ---- helpers -------------------------------------------------------
    def _session_customer(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        tok = c["sid"].value if "sid" in c else None
        cid = SESSIONS.get(tok)
        return cid, CUSTOMERS.get(cid)

    def _send(self, body, status=200, ctype="text/html; charset=utf-8", cookie=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    # ---- routing -------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        cid, me = self._session_customer()
        path = u.path

        if path == "/":
            self._send(shell(self._home(me), me))
        elif path == "/account":
            self._send(shell(self._account(me, q), me))
        elif path == "/orders":
            self._send(shell(self._orders_list(me), me))
        elif path.startswith("/orders/"):
            self._send(shell(self._order_detail(me, path.rsplit("/", 1)[-1]), me))
        elif path == "/api/order":
            self._api_order(q)                      # FLAW 2.3 (no auth)
        elif path == "/apps/rewards/admin":
            self._send(shell(self._rewards_admin(me), me))   # FLAW 2.4
        elif path == "/logout":
            self._send(shell(msg("Logged out."), None), cookie="sid=; Max-Age=0; Path=/")
        else:
            self._send(shell(msg("Not found.", ok=False), me), status=404)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":
            d = self._form()
            email = (d.get("email") or "").strip().lower()
            pw = d.get("password") or ""
            cid = EMAIL_TO_ID.get(email)
            if cid and CUSTOMERS[cid]["password"] == pw:
                tok = secrets.token_hex(16)
                SESSIONS[tok] = cid
                self._send(shell(msg(f"Signed in as {email}."), CUSTOMERS[cid]),
                           cookie=f"sid={tok}; Path=/; HttpOnly")
            else:
                self._send(shell(self._home(None) + msg("Bad credentials.", ok=False), None))
        elif u.path == "/account":
            cid, me = self._session_customer()
            self._send(shell(self._account_update(me, self._form()), me))
        else:
            cid, me = self._session_customer()
            self._send(shell(msg("Not found.", ok=False), me), status=404)

    # ---- views ---------------------------------------------------------
    def _home(self, me):
        if me:
            return "<div class='card'><h1>Welcome back</h1><p>Use the nav to view your account and orders.</p></div>"
        return ("<div class='card'><h1>Sign in</h1><h2>VAPT IDOR lab</h2>"
                "<form method='post' action='/login'>"
                "<label>Email</label><input name='email' autocomplete='off'>"
                "<label>Password</label><input name='password' type='password' autocomplete='off'>"
                "<button>Sign in</button></form></div>")

    def _account(self, me, q):
        if not me:
            return msg("Please sign in first.", ok=False)
        # FLAW 2.2 — ACCOUNT IDOR: honours ?id= from the client with no ownership
        #   check, so you can read ANY customer's profile. A secure app ignores the
        #   client id and always uses the session's own customer id.
        target_id = int(q["id"][0]) if "id" in q else me_id(me)
        c = CUSTOMERS.get(target_id)
        if not c:
            return msg("No such customer.", ok=False)
        extra = "" if target_id == me_id(me) else msg(
            f"⚠ You are viewing customer {target_id}, not yourself — IDOR!", ok=False)
        return (f"<div class='card'><h1>Account</h1>{extra}"
                f"<form method='post' action='/account'>"
                f"<input type='hidden' name='id' value='{target_id}'>"  # FLAW 2.2 again on edit
                f"<label>Name</label><input name='name' value='{html.escape(c['name'])}'>"
                f"<label>Address</label><input name='address' value='{html.escape(c['address'])}'>"
                f"<label>Phone</label><input name='phone' value='{html.escape(c['phone'])}'>"
                f"<p class='note'>Email: {html.escape(c['email'])}</p>"
                f"<button>Save</button></form>"
                f"<p class='note'>Try <code>/account?id=1002</code> while signed in as Alice.</p></div>")

    def _account_update(self, me, d):
        if not me:
            return msg("Please sign in first.", ok=False)
        # FLAW 2.2 — writes to whatever id the hidden field carries (cross-account edit)
        target_id = int(d.get("id") or me_id(me))
        c = CUSTOMERS.get(target_id)
        if not c:
            return msg("No such customer.", ok=False)
        for f in ("name", "address", "phone"):
            if f in d:
                c[f] = d[f]
        owned = target_id == me_id(me)
        return msg(f"Saved profile for customer {target_id}."
                   + ("" if owned else "  ⚠ That wasn't your account — cross-account write (IDOR)!"),
                   ok=owned)

    def _orders_list(self, me):
        if not me:
            return msg("Please sign in first.", ok=False)
        mine = {oid: o for oid, o in ORDERS.items() if o["customer"] == me_id(me)}
        rows = "".join(f"<tr><td><a href='/orders/{oid}'>#{oid}</a></td>"
                       f"<td>{o['items']}</td><td>{o['total']}</td></tr>" for oid, o in mine.items())
        return (f"<div class='card'><h1>My orders</h1><table>"
                f"<tr><th>Order</th><th>Items</th><th>Total</th></tr>{rows}</table>"
                f"<p class='note'>Order ids are sequential. Try <code>/orders/5002</code> "
                f"(Bob's) while signed in as Alice.</p></div>")

    def _order_detail(self, me, raw_id):
        if not me:
            return msg("Please sign in first.", ok=False)
        try:
            oid = int(raw_id)
        except ValueError:
            return msg("Bad order id.", ok=False)
        o = ORDERS.get(oid)
        if not o:
            return msg("No such order.", ok=False)
        # FLAW 2.1 — ORDER IDOR: returns the order WITHOUT checking o["customer"]
        #   against the session. Secure: `if o["customer"] != me_id(me): return 404`.
        foreign = o["customer"] != me_id(me)
        warn = msg(f"⚠ Order #{oid} belongs to customer {o['customer']}, not you — IDOR!",
                   ok=False) if foreign else ""
        return (f"<div class='card'><h1>Order #{oid}</h1>{warn}"
                f"<table><tr><th>Items</th><td>{html.escape(o['items'])}</td></tr>"
                f"<tr><th>Total</th><td>{o['total']}</td></tr>"
                f"<tr><th>Card</th><td>•••• {o['card_last4']}</td></tr>"
                f"<tr><th>Owner</th><td>customer {o['customer']}</td></tr></table></div>")

    def _api_order(self, q):
        # FLAW 2.3 — CUSTOM-APP ENDPOINT WITH NO AUTH: a JSON endpoint (the kind a
        #   custom app exposes) that returns any order by id to ANYONE, no session,
        #   no HMAC check. Hit it logged-out:  /api/order?id=5001
        oid = int(q["id"][0]) if "id" in q else None
        o = ORDERS.get(oid)
        if not o:
            self._send(b'{"error":"not found"}', status=404, ctype="application/json")
            return
        body = _json.dumps({"order_id": oid, **o}).encode()
        self._send(body, ctype="application/json")

    def _rewards_admin(self, me):
        # FLAW 2.4 — FORCED BROWSING: an "admin" page of a custom app with no role
        #   check. Any logged-in customer (or, as written, even anon) reaches it.
        rows = "".join(f"<tr><td>{cid}</td><td>{c['email']}</td><td>{c['name']}</td>"
                       f"<td>{c['phone']}</td></tr>" for cid, c in CUSTOMERS.items())
        return (f"<div class='card'><h1>Rewards — Admin</h1>"
                f"{msg('⚠ This page has no role check (forced browsing / broken access control).', ok=False)}"
                f"<table><tr><th>ID</th><th>Email</th><th>Name</th><th>Phone</th></tr>{rows}</table></div>")

    def log_message(self, *a):
        pass


PORT = 8001
if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"VAPT IDOR lab on http://127.0.0.1:{PORT}  (Ctrl-C to stop)")
    print("Maps to playbook Area 2: 2.1 orders, 2.2 account, 2.3 custom-app endpoint, 2.4 forced browsing.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
