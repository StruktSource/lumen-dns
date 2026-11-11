# External login (OpenID Connect)

Let people sign in to the web console with an identity provider you already run, such as **Authentik**, **Authelia**, **Pocket ID**, **Octelium**, Keycloak, or any other standard OpenID Connect provider. It is **off by default**, and the built-in username and password login always stays available, so a provider outage cannot lock you out.

> [!NOTE]
> This signs people in to the **web console** only. It does not change DNS, filtering, or the management API.

## Turn it on

You need [managed mode](managed-mode.md) (`--state`), a web listener, and a client registered with your provider:

- **Redirect URL:** `https://<your console address>/api/login/oidc/callback` (exactly this path).
- **Flow:** authorization code with PKCE. A client secret is optional.
- **Scopes:** Lumen asks for `openid profile email groups`. Providers ignore scopes they do not know.

```toml
[web.oidc]
enabled = true
label = "Authentik"                       # text of the sign-in button
issuer = "https://auth.home.example/application/o/lumen/"
client_id = "lumen"
client_secret_file = "oidc-secret"       # optional; one line, beside the config file
redirect_url = "https://dns.home.example/api/login/oidc/callback"
# ca_file = "provider-ca.pem"            # only for a provider with a private certificate authority
# username_claim = "preferred_username"  # default
# groups_claim = "groups"                # default
# admin_group = "lumen-admins"           # members start as administrators
```

Check it with `lumen --config FILE --check`, then apply it as any other configuration change. The login page then shows **Sign in with Authentik** under the password form.

| Field | Meaning |
| :--- | :--- |
| `issuer` | `https://` only. `http://` is accepted only for `localhost` or a loopback address, for testing. |
| `client_secret_file` | Read when needed, never logged or shown. Leave unset for a public client. |
| `redirect_url` | Must be registered with the provider and end in `/api/login/oidc/callback`. |
| `ca_file` | Extra trusted CA certificates (PEM, up to 1 MiB) for the provider only. |
| `admin_group` | A person in this group is created as an administrator on their **first** sign-in. |

## How it fits the existing accounts

- **An account per person.** The first sign-in creates a normal console account, named from `username_claim` (cleaned to the console's username rules). It appears under *Users & access* like any other and can be given a role or deleted there.
- **Never linked by name.** An external person is tied to the provider's stable `(issuer, subject)` pair, **not** to a username. If the provider says someone is called `admin` and a local `admin` exists, they get a separate account such as `admin-1a2b3c4d`. Nobody can take over a local account by choosing a matching name.
- **Roles.** New accounts are *User*, or *Administrator* when they are in `admin_group`. The role is set only at creation and never changed by later sign-ins, so changing it in the console sticks. Remove someone's access by deleting their account, or by removing them at the provider.
- **Two-step verification.** The provider is responsible for the second factor, so Lumen's own two-step prompt is not asked after an external sign-in.
- **Sessions** are the same as for password sign-ins: the same cookie, idle and absolute limits, and sign-out. The audit log records `sso` as the sign-in method.
- **Passwords.** An external account gets a random password nobody knows. An administrator can still set one for it under *Users & access* if you want a local fallback.

## What Lumen checks

- Provider discovery (`/.well-known/openid-configuration`) must report the configured issuer, and every endpoint must be `https`.
- The browser that started the sign-in must finish it: a short-lived `HttpOnly` cookie carries the one-time `state`, which works once and expires after 10 minutes. Starts are rate limited per address, and at most 256 sign-ins can wait at once.
- The code is exchanged **directly** with the provider's token endpoint over TLS, with the PKCE verifier. Lumen then validates the ID token's issuer, audience (and `azp` when there are several), expiry, issue time, and nonce.
- **The ID token's signature is not checked.** OpenID Connect Core (section 3.1.3.7) allows this when the token arrives straight from the token endpoint over TLS, as it does here, which is why Lumen needs no JWT or key-set code. The certificate of the provider is verified, with the bundled public roots plus any `ca_file`.
- Provider tokens are never stored. Only the issuer, the subject, and the console account are kept.
- A failed sign-in returns to the login page with one generic message. The reason goes to the audit log, never to the browser.

## Troubleshooting

| Symptom | Check |
| :--- | :--- |
| No button on the login page | `enabled = true`, the config was applied, and the console runs in managed mode. |
| "Single sign-on did not work" | The audit log shows the reason: wrong issuer, wrong client ID, an unregistered redirect URL, a clock more than 2 minutes off, or the provider being unreachable from Lumen. |
| Provider uses a private CA | Set `ca_file` to its certificate. |
| Everyone becomes a User | The provider does not send the `groups` claim for this client, or `groups_claim` has another name. |

## Not included yet

Linking an existing local account to a provider identity, mapping groups to roles on every sign-in, single logout, and a setup-wizard step. Not verified against live Authentik, Authelia, Pocket ID, or Octelium installations: the tests use a local standards-shaped provider.

## Related

- [Web console](web-console.md)
- [Configuration: web](../reference/configuration.md)
- [Threat model](../design/threat-model.md)
