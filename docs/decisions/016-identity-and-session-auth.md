# ADR 016: Identity and Session Authentication

**Date**: 2026-08-02  
**Status**: Accepted  
**Deciders**: Project maintainers

## Context

After KX and secretstream headers (PR-4), the session must bind a long-lived **device identity** without passwords on the sodchan wire (NG8). Hosts need a policy hook without the library owning a user database.

## Decision

### Device proof (client → server)

1. Client automatically sends encrypted **AUTH_DEVICE** after secretstream is ready, when `client_id_sk` is configured.
2. Signature is Ed25519 over `T_auth` (ADR 017): domain + `T_hello` + client pk + username + device_id.
3. Library **verifies** the signature before any host policy event.
4. On success: emit `SODCHAN_EVENT_AUTH_DEVICE` (`sig_ok=1`, fingerprint, username, device_id) and wait for `sodchan_auth_decide` / `sodchan_auth_decide_ex`.
5. On bad signature: queue encrypted **AUTH_FAIL** (wire reason always `UNSPEC`), emit local `AUTH_FAILED` with internal `BAD_SIG`, enter **ERROR**. **No** `auth_decide`.

### Host policy (server)

- `sodchan_auth_decide(ctx, accept)` or `sodchan_auth_decide_ex(..., claims, claims_len)`.
- `accept=1` → encrypted AUTH_OK (optional claims ≤1024), `AUTHENTICATED`, **READY**.
- `accept=0` → AUTH_FAIL (UNSPEC on wire), local `AUTH_FAILED` (`POLICY`), **ERROR**.
- Exactly once per connection; second call → `SODCHAN_ERR_STATE`.
- Library does not implement device store, revoke list, or tarpit (host responsibilities).

### Client outcome

- AUTH_OK → `AUTHENTICATED` + READY.
- AUTH_FAIL → `AUTH_FAILED` + ERROR (reconnect required).

### Anti-oracle

Wire AUTH_FAIL always uses reason `UNSPEC` and empty message. Fine-grained reasons exist only in local events/metrics.

## Consequences

- Enrollment remains HTTPS (password + device pubkey registration).
- Server hosts must call `auth_decide` promptly after `AUTH_DEVICE` or the client stalls.
- PR-6 channels only operate in READY after successful auth.
