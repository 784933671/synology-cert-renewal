# Direct LAN IP access

The user wants to open `https://10.10.10.37:18443/` directly, without editing hosts or DNS. They chose the smallest change and explicitly accept the existing public-domain certificate's IP-name warning.

## Approaches

- Selected: keep the current public-domain certificate and add the exact configured NAS IPv4 authority as an additional entry. This needs no client trust installation.
- Deferred: a private IP certificate and per-device trust installation. This adds another certificate lifecycle and TLS context selection.

## Design

Compose adds `${CERTWEB_BIND}:${CERTWEB_PORT:-18443}` to the explicitly configured Host list. The backend accepts write requests only when Origin equals `https://` plus the already validated request Host. This supports independent IP/domain login while rejecting cross-entry Origin/Host combinations. The canonical deployment Origin remains the public domain, preserving certificate renewal validation and health checks.

HTTPS, CSRF, MFA, step-up, exact Host validation, network policy and proxy-header rejection remain enforced. No certificate replacement, hosts change, DNS change, access-mode switch or forced renewal is part of this change. Each host has its own browser cookies and requires its own login.

Verify direct IP login and email verification, CSRF enforcement, exact authority rejection, crossed origins, and existing domain flows. Deployment must use the existing upgrade path and preserve private data. Actual NAS deployment requires an authenticated administrative connection.
