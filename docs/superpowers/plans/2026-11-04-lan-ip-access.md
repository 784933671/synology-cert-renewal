# Direct LAN IP access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Permit direct HTTPS access using the configured NAS LAN IPv4 and port, including login and authenticated writes.

**Architecture:** Compose derives an exact IP authority from the existing bind/port configuration. SecurityBoundary compares mutation Origin to the validated current Host. Canonical domain TLS and health checks remain unchanged.

**Tech Stack:** Python 3.12, FastAPI, httpx/unittest, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-11-04-lan-ip-access-design.md`

## Global Constraints

- No hosts/DNS/trust-store changes; the user accepts the existing certificate's IP-name warning.
- Preserve exact Host checks, HTTPS, network policy, CSRF, MFA, step-up and proxy rejection.
- Preserve canonical deployment Origin, renewal and private configuration/data.

## Review Focus

- Domain Origin sent to IP Host (and the reverse) must fail.
- An unconfigured IP or omitted/wrong port must fail.
- IP email challenge and session cookies must operate under the IP host.
- Authenticated IP writes must still need CSRF and existing authorization.
- Existing domain-only deployment.env must gain the IP authority when using upgraded Compose.

### Task 1: Add exact IP entry with same-origin writes

**Files:**
- Modify: `web/compose.yaml`, `web/backend/app.py`
- Test: `tests/test_web_api.py`, `tests/test_web_mfa.py`
- Docs: `README.md`, `web/README.md`, `web/backend/README.md`, `web/CONTRACT.md`

**Interfaces:**
- Consumes existing `CERTWEB_BIND`, `CERTWEB_PORT`, `CERTWEB_ALLOWED_HOSTS` and validated `hosts[0]`.
- Produces unchanged API payloads with support for a second exact authority.

- [ ] Add IP health/static/login/CSRF and MFA regression cases and crossed/malformed Origin cases.
- [ ] Run regression tests against unchanged production code; confirm IP mutation tests fail with origin_forbidden.
- [ ] Append bind:port to Compose's Host environment and compare mutation Origin to the validated request Host.
- [ ] Run API/MFA and relevant deployment regressions; verify domain and IP acceptance and rejection cases.
- [ ] Update access instructions, explicitly describing the retained certificate warning and separate sessions.
- [ ] Run the project's Linux CI and get an independent security/code review.
- [ ] Package the verified source and deploy through the existing upgrade flow when administrative access is available; otherwise deliver the ready package and precise manual upgrade command.
