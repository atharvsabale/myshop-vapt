#!/usr/bin/env python3
"""
VAPT practice lab — deliberately-vulnerable login / signup / password-reset page.

PURPOSE
    A safe, local, offline target for exercising the Area-1 (authentication)
    test cases from ../02-playbook.md WITHOUT touching test.myshopapps.com.
    Every flaw here is intentional and mapped to a playbook case in the comments.

RUN
    python3 login_lab.py            # serves on http://127.0.0.1:8000
    python3 login_lab.py 8080       # custom port

    Then point your browser (or Burp) at it and work through 1.1 / 1.2 / 1.3.

SAFETY
    - Binds to 127.0.0.1 only (localhost). Not reachable from the network.
    - In-memory store, no real data, no external calls. Ctrl-C to stop; state is lost.
    - This is a VULNERABLE-BY-DESIGN teaching target. Do NOT deploy it anywhere.

Seeded accounts (so enumeration/reset tests have something to hit):
    alice@example.com / Password123
    bob@example.com   / hunter2
"""
import sys
import html
import time
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# In-memory "database"
# ---------------------------------------------------------------------------
USERS = {
    "alice@example.com": {"password": "Password123"},
    "bob@example.com": {"password": "hunter2"},
}
# reset_token -> email  (see the FLAWS noted in /forgot and /reset below)
RESET_TOKENS = {}
# naive sequential id generator used to build a PREDICTABLE reset token (FLAW)
_RESET_SEQ = 1000


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------
BANNER = (
    "<div style='background:#7a1f1f;color:#fff;padding:8px 12px;font:14px system-ui'>"
    "⚠ VULNERABLE-BY-DESIGN practice lab — localhost only. Not a real system.</div>"
)

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VAPT Lab — Login</title>
<style>
  body{{font:16px system-ui;margin:0;background:#0f1115;color:#e6e6e6}}
  .wrap{{max-width:460px;margin:40px auto;padding:0 16px}}
  .card{{background:#181b22;border:1px solid #2a2f3a;border-radius:10px;padding:20px;margin:16px 0}}
  h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:16px;margin:0 0 12px;color:#9aa4b2}}
  label{{display:block;margin:10px 0 4px;color:#c3cad6;font-size:14px}}
  input{{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #2a2f3a;background:#0f1115;color:#e6e6e6}}
  button{{margin-top:14px;width:100%;padding:11px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:15px;cursor:pointer}}
  a{{color:#60a5fa}} nav{{margin:10px 0 0;font-size:14px}} nav a{{margin-right:14px}}
  .msg{{padding:10px 12px;border-radius:8px;margin:12px 0;font-size:14px}}
  .ok{{background:#14361f;color:#8ef0ab;border:1px solid #1f5a33}}
  .err{{background:#3a1420;color:#ffb3c4;border:1px solid #5a1f33}}
  .note{{color:#8b93a1;font-size:12px;margin-top:8px}}
</style></head><body>{banner}
<div class="wrap">{body}
<nav><a href="/">Login</a><a href="/signup">Sign up</a><a href="/forgot">Forgot password</a></nav>
<p class="note">Seeded: alice@example.com / Password123 &nbsp;·&nbsp; bob@example.com / hunter2</p>
</div></body></html>"""


def page(body: str) -> bytes:
    return PAGE.format(banner=BANNER, body=body).encode()


def msg(text: str, ok: bool = True) -> str:
    return f"<div class='msg {'ok' if ok else 'err'}'>{html.escape(text)}</div>"


def login_form(message: str = "") -> str:
    return (
        "<div class='card'><h1>Sign in</h1><h2>VAPT practice lab</h2>"
        + message
        + "<form method='post' action='/login'>"
        "<label>Email</label><input name='email' autocomplete='off'>"
        "<label>Password</label><input name='password' type='password' autocomplete='off'>"
        "<button>Sign in</button></form></div>"
    )


def signup_form(message: str = "") -> str:
    return (
        "<div class='card'><h1>Create account</h1><h2>VAPT practice lab</h2>"
        + message
        + "<form method='post' action='/signup'>"
        "<label>Email</label><input name='email' autocomplete='off'>"
        "<label>Password</label><input name='password' type='password' autocomplete='off'>"
        "<button>Create account</button></form></div>"
    )


def forgot_form(message: str = "") -> str:
    return (
        "<div class='card'><h1>Reset password</h1><h2>VAPT practice lab</h2>"
        + message
        + "<form method='post' action='/forgot'>"
        "<label>Email</label><input name='email' autocomplete='off'>"
        "<button>Send reset link</button></form></div>"
    )


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "VAPTLab/1.0"

    def _send(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # NOTE (playbook 5.2): no CSP / HSTS / X-Content-Type-Options set here either,
        # so this page also doubles as a header-hardening demo.
        self.end_headers()
        self.wfile.write(body)

    def _form(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    # ---- routing -------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        q = parse_qs(urlparse(self.path).query)
        if path in ("/", "/login"):
            self._send(page(login_form()))
        elif path == "/signup":
            self._send(page(signup_form()))
        elif path == "/forgot":
            self._send(page(forgot_form()))
        elif path == "/reset":
            token = (q.get("token") or [""])[0]
            self._send(page(self._reset_page(token)))
        else:
            self._send(page(msg("Not found.", ok=False)), status=404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self._form()
        if path == "/login":
            self._send(page(self._do_login(data)))
        elif path == "/signup":
            self._send(page(self._do_signup(data)))
        elif path == "/forgot":
            self._send(page(self._do_forgot(data)))
        elif path == "/reset":
            self._send(page(self._do_reset(data)))
        else:
            self._send(page(msg("Not found.", ok=False)), status=404)

    # ---- handlers (flaws are intentional & labelled) -------------------
    def _do_login(self, d):
        email = (d.get("email") or "").strip().lower()
        pw = d.get("password") or ""
        # FLAW 1.2 — USER ENUMERATION: distinct messages + timing reveal existence.
        if email not in USERS:
            return login_form(msg("No account found for that email.", ok=False))
        time.sleep(0.4)  # simulated extra work only for existing users -> timing oracle
        if USERS[email]["password"] != pw:
            return login_form(msg("Incorrect password for that account.", ok=False))
        return login_form(msg(f"Signed in as {email}. (demo — no real session)"))

    def _do_signup(self, d):
        email = (d.get("email") or "").strip().lower()
        pw = d.get("password") or ""
        if not email or "@" not in email:
            return signup_form(msg("Enter a valid email.", ok=False))
        # FLAW 1.2 — ENUMERATION: tells attacker the email is already registered.
        if email in USERS:
            return signup_form(msg("That email is already in use.", ok=False))
        # FLAW 1.1 — NO PASSWORD POLICY: accepts anything, incl. "1" or "password".
        USERS[email] = {"password": pw}
        return signup_form(msg(f"Account created for {email} with password of length {len(pw)}."))

    def _do_forgot(self, d):
        global _RESET_SEQ
        email = (d.get("email") or "").strip().lower()
        # FLAW 1.2 — ENUMERATION: only issues/acknowledges for real accounts.
        if email not in USERS:
            return forgot_form(msg("No account with that email.", ok=False))
        # FLAW 1.3 — PREDICTABLE TOKEN: sequential, not random, not bound to a secret.
        _RESET_SEQ += 1
        token = str(_RESET_SEQ)
        # FLAW 1.3 — NO EXPIRY stored; NOT invalidated when a new one is issued.
        RESET_TOKENS[token] = email
        # In a real app the link is emailed; here we print it so you can follow it.
        link = f"/reset?token={token}"
        print(f"[reset] {email} -> http://127.0.0.1:{PORT}{link}")
        return forgot_form(
            msg(f"Reset link generated (check the server console, or use): {link}")
        )

    def _reset_page(self, token):
        valid = token in RESET_TOKENS
        head = "<div class='card'><h1>Set new password</h1><h2>VAPT practice lab</h2>"
        if not valid:
            return head + msg("Invalid or unknown token.", ok=False) + "</div>"
        return (
            head
            + msg(f"Token recognised (resolves to {RESET_TOKENS[token]}).")
            + f"<form method='post' action='/reset'><input type='hidden' name='token' value='{html.escape(token)}'>"
            "<label>New password</label><input name='password' type='password'>"
            "<button>Change password</button></form></div>"
        )

    def _do_reset(self, d):
        token = d.get("token") or ""
        pw = d.get("password") or ""
        if token not in RESET_TOKENS:
            return msg("Invalid or unknown token.", ok=False)
        email = RESET_TOKENS[token]
        # FLAW 1.1 — still no policy check on the new password.
        USERS[email]["password"] = pw
        # FLAW 1.3 — TOKEN REUSE: token is NOT consumed here, so it keeps working.
        #   (A secure app would do: del RESET_TOKENS[token])
        return (
            "<div class='card'>"
            + msg(f"Password for {email} changed. (This token still works — reuse it to prove the flaw.)")
            + "</div>"
        )

    def log_message(self, fmt, *args):
        pass  # quiet; we print our own reset lines


# ---------------------------------------------------------------------------
PORT = 8000
if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"VAPT login lab on http://127.0.0.1:{PORT}  (Ctrl-C to stop)")
    print("Maps to playbook Area 1: 1.1 weak passwords, 1.2 enumeration, 1.3 reset-link reuse/expiry.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")
