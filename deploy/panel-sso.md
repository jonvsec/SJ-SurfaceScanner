# Operator console, single sign on with Microsoft Entra

The panel (`tools/panel.py`) has two auth modes.

- **Local demo** (default). One username and password read from the environment
  (`PANEL_USER`, `PANEL_PASSWORD`). Good for a dev box. Never commit the values,
  put them in `.env`, which is gitignored.
- **Production SSO**. Set `PANEL_SSO=1`. The panel then has no login of its own.
  An identity-aware proxy signs the user in against Microsoft Entra and passes
  the verified email in a header. The panel allows only addresses in
  `PANEL_EMAIL_DOMAIN` (yourcompany.com).

The panel code does not change between the two. SSO is a deployment decision.

## Why a proxy and not SAML in the app

Auth code is where a private panel gets compromised. Rather than parse SAML or
OIDC inside the panel, put `oauth2-proxy` in front of it. The proxy is a
battle-tested component that does the whole SSO exchange and forwards the
request only when the user is authenticated. The panel stays read-only and
trusts the header, which is safe because the panel binds to localhost and
nothing but the proxy can reach it.

```
VPN  ->  oauth2-proxy (Entra OIDC, yourcompany.com only)  ->  panel on 127.0.0.1
```

## In Entra, one time

1. Register an application, single tenant (the yourcompany.com tenant only).
   Single tenant alone means no outside account can get a token.
2. Add a client secret. Note tenant id, client id, secret.
3. Redirect URI is the proxy callback, for example
   `https://eas-panel.internal/oauth2/callback`.
4. On the Enterprise App, set User assignment required to Yes and assign only a
   your red team group. That is the group level gate.

## oauth2-proxy on the brain server

```
provider = "oidc"
oidc_issuer_url = "https://login.microsoftonline.com/<TENANT_ID>/v2.0"
client_id = "<CLIENT_ID>"
client_secret = "<CLIENT_SECRET>"
email_domains = ["yourcompany.com"]
upstreams = ["http://127.0.0.1:8787/"]
cookie_secret = "<32-byte-random>"
# Forward the verified email to the panel.
set_xauthrequest = true
```

Then run the panel with SSO on, bound to localhost so only the proxy reaches it:

```bash
PANEL_SSO=1 PANEL_EMAIL_DOMAIN=yourcompany.com \
    python tools/panel.py --host 127.0.0.1 --port 8787
```

## If a policy requires SAML specifically

Run oauth2-proxy with a SAML provider, or front it with mod_auth_mellon, and
have it set the same `X-Auth-Request-Email` header. Nothing in the panel
changes. OIDC is the simpler path with Entra, so prefer it unless a Security
Joes policy mandates SAML.

## Three layers of yourcompany.com only

1. Single tenant app registration, outside accounts cannot authenticate.
2. Enterprise App group assignment, only the red team group is allowed.
3. Email domain allowlist, in both the proxy and the panel.
