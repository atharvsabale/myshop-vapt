#!/usr/bin/env python3
"""
VAPT practice lab — deliberately-vulnerable cart / checkout logic (Area 4).

PURPOSE
    A safe, local, offline target for the cart & checkout business-logic cases in
    ../02-playbook.md, WITHOUT touching the real store. The server TRUSTS values a
    client controls (price, quantity, discounts), so you can tamper and watch the
    total go wrong. "Checkout" is simulated test-mode only — no real payment.

RUN
    python3 cart_lab.py            # http://127.0.0.1:8003
    python3 cart_lab.py 8090       # custom port

SAFETY
    - 127.0.0.1 only. In-memory, per-session cart. Ctrl-C to stop.
    - VULNERABLE-BY-DESIGN teaching target. Do NOT deploy it anywhere.

The flaws (labelled "# FLAW 4.x") map to the playbook:
    4.1 Price tampering     -> /cart/add trusts a client-supplied `price`
    4.2 Negative quantity   -> `qty` may be negative/zero -> negative line total (credit)
    4.3 Discount reuse/stack -> codes can be applied repeatedly and stacked
    4.4 Rounding/logic      -> totals derive from tampered inputs, no server re-check
"""
import sys
import html
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

# Real catalogue (what a secure server would charge from) --------------------
CATALOG = {
    "mug":   {"name": "Blue Mug",   "price": 10.00},
    "shirt": {"name": "Logo Shirt", "price": 25.00},
    "hat":   {"name": "Beanie",     "price": 15.00},
}
# Discount codes the store intends. All are meant to be single-use / non-stacking.
CODES = {
    "SAVE10":   {"kind": "percent", "value": 10, "desc": "10% off (intended once)"},
    "FIVEOFF":  {"kind": "fixed",   "value": 5.00, "desc": "£5 off (intended once)"},
}

CARTS = {}  # sid -> {"items":[{product,qty,price}], "codes":[code,...]}

BANNER = ("<div style='background:#7a1f1f;color:#fff;padding:8px 12px;font:14px system-ui'>"
          "⚠ VULNERABLE-BY-DESIGN practice lab — localhost only. Test-mode checkout, no real payment.</div>")
CSS = """<style>
 body{font:16px system-ui;margin:0;background:#0f1115;color:#e6e6e6}
 .wrap{max-width:660px;margin:26px auto;padding:0 16px}
 .card{background:#181b22;border:1px solid #2a2f3a;border-radius:10px;padding:16px;margin:14px 0}
 h1{font-size:19px;margin:0 0 4px} h2{font-size:14px;color:#9aa4b2;margin:0 0 10px}
 .case{color:#60a5fa;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
 table{width:100%;border-collapse:collapse;font-size:14px} td,th{border-bottom:1px solid #2a2f3a;padding:6px 8px;text-align:left}
 th{color:#9aa4b2} .tot td{border:0;padding:3px 8px} .grand{font-size:18px;font-weight:700}
 .neg{color:#ff7a97} a{color:#60a5fa} nav a{margin-right:12px;font-size:14px}
 code{background:#11141a;padding:1px 5px;border-radius:5px} .note{color:#8b93a1;font-size:12px}
 .msg{padding:9px 12px;border-radius:8px;margin:10px 0;font-size:14px}
 .ok{background:#14361f;color:#8ef0ab;border:1px solid #1f5a33}
 .err{background:#3a1420;color:#ffb3c4;border:1px solid #5a1f33}
</style>"""


def shell(body):
    nav = "<nav><a href='/'>Shop</a><a href='/cart'>Cart</a></nav>"
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>VAPT Cart Lab</title>{CSS}</head><body>{BANNER}"
            f"<div class='wrap'>{nav}{body}</div></body></html>").encode()


def money(x):
    return ("-£%.2f" % -x) if x < 0 else ("£%.2f" % x)


class Handler(BaseHTTPRequestHandler):
    server_version = "VAPTLab/1.0"

    def _sid(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        sid = c["sid"].value if "sid" in c else None
        if sid not in CARTS:
            sid = secrets.token_hex(8)
            CARTS[sid] = {"items": [], "codes": []}
            self._set_cookie = f"sid={sid}; Path=/; HttpOnly"
        else:
            self._set_cookie = None
        return sid

    def _send(self, body, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if getattr(self, "_set_cookie", None):
            self.send_header("Set-Cookie", self._set_cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _args(self, u):
        q = parse_qs(urlparse(u).query)
        return {k: v[0] for k, v in q.items()}

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def do_GET(self):
        sid = self._sid()
        p = urlparse(self.path).path
        if p == "/":
            self._send(shell(self._shop()))
        elif p == "/cart":
            self._send(shell(self._cart(sid)))
        elif p == "/cart/add":                 # GET add, for easy curl/Burp tampering
            self._add(sid, self._args(self.path))
            self._send(shell(self._cart(sid)))
        elif p == "/cart/clear":
            CARTS[sid] = {"items": [], "codes": []}
            self._send(shell(self._cart(sid)))
        elif p == "/discount":
            self._send(shell(self._discount(sid, self._args(self.path))))
        elif p == "/checkout":
            self._send(shell(self._checkout(sid)))
        else:
            self._send(shell("<div class='card'>Not found.</div>"), status=404)

    def do_POST(self):
        sid = self._sid()
        p = urlparse(self.path).path
        if p == "/cart/add":
            self._add(sid, self._form())
            self._send(shell(self._cart(sid)))
        elif p == "/discount":
            self._send(shell(self._discount(sid, self._form())))
        else:
            self._send(shell("<div class='card'>Not found.</div>"), status=404)

    # ---- logic (flaws are intentional) --------------------------------
    def _add(self, sid, d):
        product = d.get("product", "")
        if product not in CATALOG:
            return
        # FLAW 4.2 — trusts qty verbatim, incl. negative/zero (no `qty >= 1` check).
        try:
            qty = int(d.get("qty", "1"))
        except ValueError:
            qty = 1
        # FLAW 4.1 — PRICE TAMPERING: if the request carries a price, the server
        #   uses it instead of CATALOG[product]["price"]. Secure servers ignore any
        #   client price and always look it up.
        if "price" in d:
            try:
                price = float(d["price"])
            except ValueError:
                price = CATALOG[product]["price"]
        else:
            price = CATALOG[product]["price"]
        CARTS[sid]["items"].append({"product": product, "qty": qty, "price": price})

    def _discount(self, sid, d):
        code = (d.get("code", "") or "").upper()
        if code not in CODES:
            return self._cart(sid, msg=("Unknown code.", False))
        # FLAW 4.3 — DISCOUNT REUSE/STACKING: appended every time, no check that it
        #   was already used, no "one code per order" rule.
        CARTS[sid]["codes"].append(code)
        return self._cart(sid, msg=(f"Applied {code}. (codes on cart: {', '.join(CARTS[sid]['codes'])})", True))

    def _totals(self, sid):
        cart = CARTS[sid]
        subtotal = sum(i["qty"] * i["price"] for i in cart["items"])  # may be negative (4.2)
        discount = 0.0
        for code in cart["codes"]:
            c = CODES[code]
            # FLAW 4.4 — discount computed on the (tamperable) running subtotal with
            #   no floor; stacking several can exceed the subtotal.
            discount += subtotal * c["value"] / 100.0 if c["kind"] == "percent" else c["value"]
        total = subtotal - discount
        return subtotal, discount, total

    def _shop(self):
        rows = "".join(
            f"<tr><td>{v['name']}</td><td>£{v['price']:.2f}</td>"
            f"<td><a href='/cart/add?product={k}&qty=1'>Add</a></td></tr>"
            for k, v in CATALOG.items())
        return (f"<div class='card'><h1>Shop</h1><table>"
                f"<tr><th>Item</th><th>Price</th><th></th></tr>{rows}</table>"
                f"<p class='note'>The add-to-cart request takes <code>product</code>, <code>qty</code> and "
                f"(if you add it) <code>price</code>. Try "
                f"<code>/cart/add?product=mug&amp;qty=2&amp;price=0.01</code> or "
                f"<code>?qty=-3</code>.</p></div>")

    def _cart(self, sid, msg=None):
        cart = CARTS[sid]
        rows = ""
        for i in cart["items"]:
            line = i["qty"] * i["price"]
            cls = " class='neg'" if line < 0 else ""
            rows += (f"<tr><td>{CATALOG[i['product']]['name']}</td><td>{i['qty']}</td>"
                     f"<td>£{i['price']:.2f}</td><td{cls}>{money(line)}</td></tr>")
        if not rows:
            rows = "<tr><td colspan='4' class='note'>Cart is empty.</td></tr>"
        subtotal, discount, total = self._totals(sid)
        m = f"<div class='msg {'ok' if msg[1] else 'err'}'>{html.escape(msg[0])}</div>" if msg else ""
        tcls = " neg" if total < 0 else ""
        return (f"<div class='card'><div class='case'>Cases 4.1–4.4 · Cart &amp; checkout</div>"
                f"<h1>Your cart</h1>{m}"
                f"<table><tr><th>Item</th><th>Qty</th><th>Unit</th><th>Line</th></tr>{rows}</table>"
                f"<table style='margin-top:8px'>"
                f"<tr class='tot'><td>Subtotal</td><td>{money(subtotal)}</td></tr>"
                f"<tr class='tot'><td>Discounts ({len(cart['codes'])})</td><td>{money(-discount)}</td></tr>"
                f"<tr class='tot grand{tcls}'><td>Total</td><td>{money(total)}</td></tr></table>"
                f"<form method='get' action='/discount' style='margin-top:10px'>"
                f"<input name='code' placeholder='SAVE10 / FIVEOFF'>"
                f"<button>Apply code</button></form>"
                f"<p style='margin-top:10px'><a href='/checkout'>Proceed to checkout (test mode)</a> · "
                f"<a href='/cart/clear'>Clear</a></p>"
                f"<p class='note'>Codes: SAVE10 (10%), FIVEOFF (£5). Apply the same one twice and watch it stack.</p>"
                f"</div>")

    def _checkout(self, sid):
        subtotal, discount, total = self._totals(sid)
        warn = ""
        if total <= 0:
            warn = "<div class='msg err'>⚠ Order total is £0 or negative — the store would ship for free / owe the buyer.</div>"
        return (f"<div class='card'><div class='case'>Checkout · test mode</div>"
                f"<h1>Order confirmation (Bogus Gateway)</h1>{warn}"
                f"<table><tr><td>Subtotal</td><td>{money(subtotal)}</td></tr>"
                f"<tr><td>Discounts</td><td>{money(-discount)}</td></tr>"
                f"<tr class='grand'><td>Charged</td><td>{money(total)}</td></tr></table>"
                f"<p class='note'>Test mode only — no real card processed. This is where you'd confirm the "
                f"tampered total actually completes an order.</p></div>")

    def log_message(self, *a):
        pass


PORT = 8003
if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"VAPT cart lab on http://127.0.0.1:{PORT}  (Ctrl-C to stop)")
    print("Maps to playbook Area 4: 4.1 price, 4.2 negative qty, 4.3 discount reuse, 4.4 totals.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
