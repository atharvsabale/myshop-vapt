#!/usr/bin/env python3
"""
VAPT practice lab — deliberately-vulnerable input-handling app (Area 3: XSS & injection).

PURPOSE
    A safe, local, offline target for the input-validation test cases in
    ../02-playbook.md, WITHOUT touching the real store. It reflects and stores
    user input UNSAFELY so you can see exactly where encoding is missing.

RUN
    python3 xss_lab.py            # http://127.0.0.1:8002
    python3 xss_lab.py 8089       # custom port

SAFETY
    - 127.0.0.1 only. In-memory, no real data. Ctrl-C to stop.
    - VULNERABLE-BY-DESIGN teaching target. Do NOT deploy it anywhere.
    - The SSTI demo only evaluates a whitelisted arithmetic grammar ([0-9 +-*/()]),
      so it shows the flaw (`{{7*7}}` -> 49) without real code execution on your box.

The flaws (labelled "# FLAW 3.x") map to the playbook:
    3.1 Reflected XSS          -> /search?q= echoes q into HTML unescaped
    3.2 Stored XSS             -> /reviews stores a review and renders it unescaped
    3.3 Attribute/HTML inject  -> /greet?name= lands inside an attribute, unquoted
    3.4 Server-side template    -> /render?t= evaluates {{ ... }} (SSTI demo)
    3.5 Open redirect           -> /go?next= redirects off-site with no allow-list
"""
import re
import sys
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

REVIEWS = [  # seed one safe review so the page isn't empty
    {"author": "sam", "body": "Great mug, arrived quickly."},
]

BANNER = ("<div style='background:#7a1f1f;color:#fff;padding:8px 12px;font:14px system-ui'>"
          "⚠ VULNERABLE-BY-DESIGN practice lab — localhost only. Not a real system.</div>")
CSS = """<style>
 body{font:16px system-ui;margin:0;background:#0f1115;color:#e6e6e6}
 .wrap{max-width:640px;margin:28px auto;padding:0 16px}
 .card{background:#181b22;border:1px solid #2a2f3a;border-radius:10px;padding:16px;margin:14px 0}
 h1{font-size:19px;margin:0 0 4px} h2{font-size:14px;color:#9aa4b2;margin:0 0 10px}
 .case{color:#60a5fa;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
 label{display:block;margin:8px 0 4px;color:#c3cad6;font-size:14px}
 input{width:100%;box-sizing:border-box;padding:9px;border-radius:8px;border:1px solid #2a2f3a;background:#0f1115;color:#e6e6e6}
 button{margin-top:10px;padding:9px 15px;border:0;border-radius:8px;background:#3b82f6;color:#fff;cursor:pointer}
 a{color:#60a5fa} nav a{margin-right:12px;font-size:14px} .note{color:#8b93a1;font-size:12px}
 .out{background:#11141a;border:1px dashed #2a2f3a;border-radius:8px;padding:10px;margin-top:10px}
 code{background:#11141a;padding:1px 5px;border-radius:5px} .rev{border-top:1px solid #2a2f3a;padding:8px 0}
</style>"""


def shell(body):
    nav = ("<nav><a href='/'>Home</a><a href='/search?q=mug'>Search</a>"
           "<a href='/reviews'>Reviews</a><a href='/greet?name=friend'>Greet</a>"
           "<a href='/render?t=hello'>Template</a></nav>")
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>VAPT XSS Lab</title>{CSS}</head><body>{BANNER}"
            f"<div class='wrap'>{nav}{body}"
            f"<p class='note'>Try payloads like <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>, "
            f"<code>&lt;img src=x onerror=alert(1)&gt;</code>, <code>{{{{7*7}}}}</code>.</p>"
            f"</div></body></html>").encode()


# Whitelisted arithmetic only — safe stand-in for a template engine, proves SSTI
# without executing arbitrary code on the host.
_ARITH = re.compile(r"^[0-9+\-*/().\s]+$")


def _eval_expr(expr):
    expr = expr.strip()
    if not expr or not _ARITH.match(expr):
        return None
    try:
        return eval(expr, {"__builtins__": {}}, {})  # grammar-restricted above
    except Exception:
        return None


def _render_template(t):
    # FLAW 3.4 — SSTI: interpolates {{ ... }} by evaluating the contents.
    def repl(m):
        v = _eval_expr(m.group(1))
        return str(v) if v is not None else m.group(0)
    return re.sub(r"\{\{(.*?)\}\}", repl, t)


class Handler(BaseHTTPRequestHandler):
    server_version = "VAPTLab/1.0"

    def _send(self, body, status=200, headers=None):
        self.send_response(status)
        for k, v in (headers or {"Content-Type": "text/html; charset=utf-8"}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path
        if p == "/":
            self._send(shell(self._home()))
        elif p == "/search":
            self._send(shell(self._search(q.get("q", [""])[0])))
        elif p == "/reviews":
            self._send(shell(self._reviews()))
        elif p == "/greet":
            self._send(shell(self._greet(q.get("name", [""])[0])))
        elif p == "/render":
            self._send(shell(self._render(q.get("t", [""])[0])))
        elif p == "/go":
            self._go(q.get("next", [""])[0])
        else:
            self._send(shell("<div class='card'>Not found.</div>"), status=404)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/reviews":
            d = self._form()
            REVIEWS.append({"author": d.get("author", "anon"), "body": d.get("body", "")})
            self._send(shell(self._reviews()))
        else:
            self._send(shell("<div class='card'>Not found.</div>"), status=404)

    # ---- views ---------------------------------------------------------
    def _home(self):
        return ("<div class='card'><h1>Input-handling lab</h1>"
                "<p>Five surfaces, each with an intentional flaw. Use the nav.</p>"
                "<p class='note'>Compare with how a safe app would HTML-encode on output.</p></div>")

    def _search(self, q):
        # FLAW 3.1 — REFLECTED XSS: q is concatenated into HTML with no encoding.
        #   Secure: html.escape(q).
        return (f"<div class='card'><div class='case'>Case 3.1 · Reflected XSS</div>"
                f"<h1>Search</h1><h2>Results for your query</h2>"
                f"<form method='get' action='/search'><label>Query</label>"
                f"<input name='q' value=\"{q}\"><button>Search</button></form>"  # also attr-context
                f"<div class='out'>You searched for: {q}</div>"  # <-- unescaped reflection
                f"<p class='note'>Try <code>q=&lt;script&gt;alert(1)&lt;/script&gt;</code> or "
                f"<code>\"&gt;&lt;svg onload=alert(1)&gt;</code>.</p></div>")

    def _reviews(self):
        # FLAW 3.2 — STORED XSS: review body rendered without encoding on every view.
        items = "".join(f"<div class='rev'><b>{r['author']}</b>: {r['body']}</div>" for r in REVIEWS)
        return (f"<div class='card'><div class='case'>Case 3.2 · Stored XSS</div>"
                f"<h1>Product reviews</h1>"
                f"<form method='post' action='/reviews'>"
                f"<label>Name</label><input name='author'>"
                f"<label>Review</label><input name='body'>"
                f"<button>Post review</button></form>"
                f"<div style='margin-top:10px'>{items}</div>"
                f"<p class='note'>Post <code>&lt;img src=x onerror=alert(1)&gt;</code>; it fires for "
                f"every visitor who opens this page afterwards.</p></div>")

    def _greet(self, name):
        # FLAW 3.3 — ATTRIBUTE-CONTEXT INJECTION: value lands inside an UNQUOTED
        #   attribute, so `name=x onmouseover=alert(1)` breaks out without needing <>.
        return (f"<div class='card'><div class='case'>Case 3.3 · Attribute / HTML injection</div>"
                f"<h1>Greeting</h1>"
                f"<div class='out'><span data-user={name}>Hello, {name}!</span></div>"
                f"<p class='note'>Try <code>name=x onmouseover=alert(1) y</code> (unquoted-attribute "
                f"breakout) or <code>name=\"&gt;&lt;b&gt;bold</code>.</p></div>")

    def _render(self, t):
        rendered = _render_template(t)  # FLAW 3.4 (and still unescaped -> stacks with XSS)
        return (f"<div class='card'><div class='case'>Case 3.4 · Server-side template injection</div>"
                f"<h1>Template preview</h1>"
                f"<form method='get' action='/render'><label>Template</label>"
                f"<input name='t' value=\"{html.escape(t)}\"><button>Render</button></form>"
                f"<div class='out'>{rendered}</div>"
                f"<p class='note'>Try <code>t={{{{7*7}}}}</code> — if it prints <code>49</code>, "
                f"your input reached a template engine.</p></div>")

    def _go(self, nxt):
        # FLAW 3.5 — OPEN REDIRECT: redirects to any URL with no allow-list check.
        if not nxt:
            self._send(shell("<div class='card'><div class='case'>Case 3.5 · Open redirect</div>"
                             "<h1>Redirector</h1><p>Add <code>?next=https://example.com</code>.</p>"
                             "<p class='note'>A safe app only allows same-site paths.</p></div>"))
            return
        self._send(b"", status=302, headers={"Location": nxt, "Content-Type": "text/plain"})

    def log_message(self, *a):
        pass


PORT = 8002
if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"VAPT XSS lab on http://127.0.0.1:{PORT}  (Ctrl-C to stop)")
    print("Maps to playbook Area 3: 3.1 reflected, 3.2 stored, 3.3 attribute, 3.4 SSTI, 3.5 open redirect.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
