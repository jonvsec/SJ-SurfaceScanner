# Security standards

Read this before touching a console route, a request handler, or any code that
fetches a URL. It maps the OWASP Top 10 (2021) to concrete, checkable rules for
this app. These are rules, not a guarantee. They are backed by checks where a
check is possible, and by a security review on every route or fetch change.

## Threat model in one paragraph

The operator console `tools/panel.py` binds to `127.0.0.1` and is a
single-operator, read-only view. Sign-in is done by a reverse proxy (for example
Entra SSO) that passes a verified email header, which the panel trusts and
restricts to `ALLOWED_EMAIL_DOMAIN`. The scanner itself fetches attacker
influenced URLs by design. So the two sharpest surfaces are request-supplied
identifiers that reach the filesystem (access control) and the outbound fetch
path (SSRF).

## The Top 10, mapped

**A01 Broken access control.**
Rule: every request-supplied slug, id or path is validated against the known set
before it reaches the filesystem. Never build a path from raw user input. Use
`_safe_token` for any value that becomes a filename or path component. The model
is single-operator today, so if the console ever serves more than one operator,
every engagement access must be authorized against the session, not assumed.
Check: a test that a crafted slug or `..` path cannot read outside the
engagement's own directory.

**A02 Cryptographic and secret failures.**
Rule: no secret or other engagement's data ever appears in a response or in
rendered HTML. Session cookies stay signed with `PANEL_SECRET` (HMAC). Secrets
come only from the environment or the data root, never from code.
Check: the pre-commit guard blocks secrets in the repo.

**A03 Injection.**
Rule: all dynamic text rendered into HTML goes through `_esc`. No HTML is built
by concatenating unescaped input. Control actions shell out only through the
guarded path, never by string-building a command. Never use `eval`,
`exec` or an equivalent on input.
Check: grep that user-facing interpolation is wrapped in `_esc`.

**A04 Insecure design.**
Rule: the console stays read-only over signals. Triage and control state change
only on an explicit operator action, never as a side effect of a view or a scan
(constitution principle 7).

**A05 Security misconfiguration.**
Rule: the console binds to `127.0.0.1` only. No debug mode, no stack trace and
no internal path is ever returned to the client. Errors return a short message,
the detail goes to the log.

**A06 Vulnerable and outdated components.**
Rule: dependencies are pinned in `uv.lock`. Keep them current and do not add a
dependency to the scanning flow without a reason, the flow stays standard
library first (constitution principle 4).

**A07 Identification and authentication failures.**
Rule: the panel trusts the proxy's verified email header and allows only
`ALLOWED_EMAIL_DOMAIN`. It never rolls its own password login. No endpoint
reveals whether a user or an engagement exists to an unauthenticated caller.

**A08 Software and data integrity failures.**
Rule: signed cookies are verified before use (reject on a bad MAC). Do not add a
broad catch-all `except` that swallows an auth or integrity failure and lets the
request continue. Fail closed.

**A09 Security logging and monitoring failures.**
Rule: `_audit` records sign-in, every control action and every triage action.
Keep that call on any new state-changing route. Never log a secret, a credential
or client data into the audit trail.

**A10 Server-side request forgery (SSRF).**
This is the one most specific to this app, because the scanner fetches URLs that
a target can influence. Rule: the scanner's fetch path is never reachable from
console user input. An outbound fetch respects the scope gate, does not follow a
redirect into a private or link-local range, and never returns raw internal
response bytes to the operator view. Treat any new fetch as semi or active scope
until proven passive.

## Two reminders

- Fixing an access-control or injection flaw that already exists in the console
  is its own spec'd slice. These rules stop new ones, they do not retroactively
  fix the old.
- AI guidance is defense in depth, not the only control. Where a static analysis
  pass (for example semgrep) can assert one of these rules, prefer the pass over
  trusting the prose.
