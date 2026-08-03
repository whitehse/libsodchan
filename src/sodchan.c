/**
 * @file sodchan.c
 * @brief libsodchan core — pure state machine (no sockets).
 *
 * PR-4: HELLO + K16 server id_sig + KX + secretstream headers.
 * PR-5: AUTH_DEVICE / auth_decide / AUTH_OK|FAIL over secretstream → READY.
 */

#include "sodchan_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t cfg_default_size(size_t v, size_t d)
{
    return v ? v : d;
}

static uint32_t cfg_default_u32(uint32_t v, uint32_t d)
{
    return v ? v : d;
}

static char *cfg_dup(sodchan_ctx_t *ctx, const char *s)
{
    size_t n;
    char *p;

    if (!s) {
        return NULL;
    }
    n = strlen(s) + 1;
    if (ctx->cfg_store_used + n > sizeof(ctx->cfg_store)) {
        return NULL;
    }
    p = ctx->cfg_store + ctx->cfg_store_used;
    memcpy(p, s, n);
    ctx->cfg_store_used += n;
    return p;
}

static void copy_key(uint8_t *dst, const uint8_t *src, size_t n, int *have)
{
    if (src) {
        memcpy(dst, src, n);
        *have = 1;
    } else {
        memset(dst, 0, n);
        *have = 0;
    }
}

void sodchan_i_set_error(sodchan_ctx_t *ctx, int code, const char *fmt, ...)
{
    va_list ap;
    sodchan_event_t ev;

    if (!ctx) {
        return;
    }
    ctx->error = code ? code : SODCHAN_ERR_PROTOCOL;
    ctx->state = SODCHAN_STATE_ERROR;
    va_start(ap, fmt);
    vsnprintf(ctx->error_msg, sizeof(ctx->error_msg), fmt, ap);
    va_end(ap);

    memset(&ev, 0, sizeof(ev));
    ev.type = SODCHAN_EVENT_ERROR;
    ev.u.error.code = ctx->error;
    memcpy(ev.u.error.message, ctx->error_msg, sizeof(ev.u.error.message));
    (void)sodchan_i_queue_event(ctx, &ev);
}

int sodchan_i_queue_event(sodchan_ctx_t *ctx, const sodchan_event_t *ev)
{
    size_t idx;

    if (!ctx || !ev || !ctx->events) {
        return SODCHAN_ERR_PARAM;
    }
    if (ctx->event_count >= ctx->event_cap) {
        return SODCHAN_ERR_FULL;
    }
    idx = (ctx->event_head + ctx->event_count) % ctx->event_cap;
    ctx->events[idx] = *ev;
    ctx->event_count++;
    return SODCHAN_OK;
}

static void out_compact(sodchan_ctx_t *ctx)
{
    if (ctx->out_off == 0) {
        return;
    }
    if (ctx->out_off >= ctx->out_len) {
        ctx->out_off = 0;
        ctx->out_len = 0;
        return;
    }
    memmove(ctx->out_buf, ctx->out_buf + ctx->out_off,
            ctx->out_len - ctx->out_off);
    ctx->out_len -= ctx->out_off;
    ctx->out_off = 0;
}

static int out_append(sodchan_ctx_t *ctx, const uint8_t *p, size_t n)
{
    out_compact(ctx);
    if (n > sizeof(ctx->out_buf) - ctx->out_len) {
        return SODCHAN_ERR_FULL;
    }
    memcpy(ctx->out_buf + ctx->out_len, p, n);
    ctx->out_len += n;
    return SODCHAN_OK;
}

static int out_append_frame(sodchan_ctx_t *ctx, const uint8_t *body,
                            size_t body_len)
{
    uint8_t frame[4 + SODCHAN_MAX_CLEAR_FRAME];
    size_t flen = 0;
    int rc;

    rc = sodchan_wire_frame_encode(body, body_len, frame, sizeof(frame), &flen);
    if (rc != SODCHAN_OK) {
        return rc;
    }
    return out_append(ctx, frame, flen);
}

static void apply_config_defaults(sodchan_ctx_t *ctx, const sodchan_config_t *cfg)
{
    ctx->event_queue_size = cfg_default_size(cfg->event_queue_size,
                                             SODCHAN_DEFAULT_EVENT_QUEUE);
    ctx->max_record_size = cfg_default_size(cfg->max_record_size,
                                            SODCHAN_DEFAULT_MAX_RECORD);
    ctx->max_channel_data = cfg_default_size(cfg->max_channel_data,
                                             SODCHAN_DEFAULT_MAX_CHANNEL);
    ctx->max_channels = cfg_default_size(cfg->max_channels,
                                         SODCHAN_DEFAULT_MAX_CHANNELS);
    if (ctx->max_channels > SODCHAN_MAX_CHANNELS) {
        ctx->max_channels = SODCHAN_MAX_CHANNELS;
    }
    ctx->initial_window = cfg_default_u32(cfg->initial_window,
                                          SODCHAN_DEFAULT_INIT_WINDOW);
    ctx->max_packet = cfg_default_u32(cfg->max_packet,
                                      SODCHAN_DEFAULT_MAX_PACKET);
    ctx->accept_any_server_pk = cfg->accept_any_server_pk ? 1 : 0;
    ctx->lab_mode = cfg->lab_mode ? 1 : 0;

    copy_key(ctx->client_id_pk, cfg->client_id_pk, SODCHAN_PUBKEY_BYTES,
             &ctx->have_client_id_pk);
    copy_key(ctx->client_id_sk, cfg->client_id_sk, SODCHAN_SECKEY_BYTES,
             &ctx->have_client_id_sk);
    copy_key(ctx->server_id_pk, cfg->server_id_pk, SODCHAN_PUBKEY_BYTES,
             &ctx->have_server_id_pk);
    copy_key(ctx->server_id_sk, cfg->server_id_sk, SODCHAN_SECKEY_BYTES,
             &ctx->have_server_id_sk);

    ctx->cfg_store_used = 0;
    ctx->allowed_channels = cfg_dup(ctx, cfg->allowed_channels);
    ctx->client_username = cfg_dup(ctx, cfg->client_username);
    ctx->client_device_id = cfg_dup(ctx, cfg->client_device_id);
}

static int derive_ss_keys_client(sodchan_ctx_t *ctx)
{
    uint8_t rx[crypto_kx_SESSIONKEYBYTES];
    uint8_t tx[crypto_kx_SESSIONKEYBYTES];

    if (crypto_kx_client_session_keys(rx, tx, ctx->eph_pk, ctx->eph_sk,
                                      ctx->peer_eph_pk) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    /* Client: c2s from tx, s2c from rx */
    if (sodchan_crypto_ss_key_derive(tx, SODCHAN_DOM_SS_C2S,
                                     ctx->ss_key_c2s) != SODCHAN_OK ||
        sodchan_crypto_ss_key_derive(rx, SODCHAN_DOM_SS_S2C,
                                     ctx->ss_key_s2c) != SODCHAN_OK) {
        sodium_memzero(rx, sizeof(rx));
        sodium_memzero(tx, sizeof(tx));
        return SODCHAN_ERR_CRYPTO;
    }
    sodium_memzero(rx, sizeof(rx));
    sodium_memzero(tx, sizeof(tx));
    return SODCHAN_OK;
}

static int derive_ss_keys_server(sodchan_ctx_t *ctx)
{
    uint8_t rx[crypto_kx_SESSIONKEYBYTES];
    uint8_t tx[crypto_kx_SESSIONKEYBYTES];

    if (crypto_kx_server_session_keys(rx, tx, ctx->eph_pk, ctx->eph_sk,
                                      ctx->peer_eph_pk) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    /* Server: c2s from rx, s2c from tx */
    if (sodchan_crypto_ss_key_derive(rx, SODCHAN_DOM_SS_C2S,
                                     ctx->ss_key_c2s) != SODCHAN_OK ||
        sodchan_crypto_ss_key_derive(tx, SODCHAN_DOM_SS_S2C,
                                     ctx->ss_key_s2c) != SODCHAN_OK) {
        sodium_memzero(rx, sizeof(rx));
        sodium_memzero(tx, sizeof(tx));
        return SODCHAN_ERR_CRYPTO;
    }
    sodium_memzero(rx, sizeof(rx));
    sodium_memzero(tx, sizeof(tx));
    return SODCHAN_OK;
}

static int queue_local_hello(sodchan_ctx_t *ctx)
{
    sodchan_hello_t h;
    uint8_t body[SODCHAN_HELLO_BODY_LEN];
    size_t blen = 0;
    int rc;

    memset(&h, 0, sizeof(h));
    h.proto_version = SODCHAN_PROTO_VERSION;
    h.suite_id = SODCHAN_SUITE_V1;
    h.role = (uint16_t)ctx->role;
    h.flags = 0;
    memcpy(h.eph_pk, ctx->eph_pk, 32);

    if (ctx->role == SODCHAN_ROLE_SERVER) {
        if (!ctx->have_peer_eph) {
            return SODCHAN_ERR_STATE;
        }
        memcpy(h.id_pk, ctx->server_id_pk, 32);
        if (sodchan_wire_build_t_hello(SODCHAN_PROTO_VERSION, SODCHAN_SUITE_V1,
                                       ctx->peer_eph_pk, ctx->eph_pk,
                                       ctx->server_id_pk,
                                       ctx->t_hello) != SODCHAN_OK) {
            return SODCHAN_ERR_PROTOCOL;
        }
        ctx->have_t_hello = 1;
        if (crypto_sign_detached(h.id_sig, NULL, ctx->t_hello,
                                 SODCHAN_T_HELLO_LEN,
                                 ctx->server_id_sk) != 0) {
            return SODCHAN_ERR_CRYPTO;
        }
    } else {
        if (ctx->have_client_id_pk) {
            memcpy(h.id_pk, ctx->client_id_pk, 32);
        }
        /* client id_sig remains zero */
    }

    rc = sodchan_wire_hello_encode(&h, body, sizeof(body), &blen);
    if (rc != SODCHAN_OK) {
        return rc;
    }
    return out_append_frame(ctx, body, blen);
}

static int client_send_ss_header_c2s(sodchan_ctx_t *ctx)
{
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (crypto_secretstream_xchacha20poly1305_init_push(&ctx->ss_push, header,
                                                        ctx->ss_key_c2s) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    ctx->ss_push_ready = 1;
    return out_append_frame(ctx, header, sizeof(header));
}

static int server_send_ss_header_s2c(sodchan_ctx_t *ctx)
{
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (crypto_secretstream_xchacha20poly1305_init_push(&ctx->ss_push, header,
                                                        ctx->ss_key_s2c) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    ctx->ss_push_ready = 1;
    return out_append_frame(ctx, header, sizeof(header));
}

static void emit_hello_received(sodchan_ctx_t *ctx)
{
    sodchan_event_t ev;

    memset(&ev, 0, sizeof(ev));
    ev.type = SODCHAN_EVENT_HELLO_RECEIVED;
    if (ctx->have_peer_id) {
        memcpy(ev.u.auth.peer_id_pk, ctx->peer_id_pk, SODCHAN_PUBKEY_BYTES);
    }
    (void)sodchan_i_queue_event(ctx, &ev);
}

static void emit_kx_complete(sodchan_ctx_t *ctx)
{
    sodchan_event_t ev;

    memset(&ev, 0, sizeof(ev));
    ev.type = SODCHAN_EVENT_KX_COMPLETE;
    (void)sodchan_i_queue_event(ctx, &ev);
}

static void emit_authenticated(sodchan_ctx_t *ctx)
{
    sodchan_event_t ev;

    memset(&ev, 0, sizeof(ev));
    ev.type = SODCHAN_EVENT_AUTHENTICATED;
    (void)sodchan_i_queue_event(ctx, &ev);
}

static void emit_auth_failed(sodchan_ctx_t *ctx, int reason, const char *msg)
{
    sodchan_event_t ev;

    memset(&ev, 0, sizeof(ev));
    ev.type = SODCHAN_EVENT_AUTH_FAILED;
    ev.u.error.code = reason;
    if (msg) {
        snprintf(ev.u.error.message, sizeof(ev.u.error.message), "%s", msg);
    }
    (void)sodchan_i_queue_event(ctx, &ev);
}

/** Max ciphertext body on wire (plaintext record + secretstream ABYTES). */
static uint32_t ss_frame_max_body(const sodchan_ctx_t *ctx)
{
    size_t m = ctx->max_record_size + crypto_secretstream_xchacha20poly1305_ABYTES;
    if (m > 0xFFFFFFFFu) {
        m = 0xFFFFFFFFu;
    }
    /* Keep within input buffer for a single frame */
    if (m + 4 > SODCHAN_IN_BUF_SIZE) {
        m = SODCHAN_IN_BUF_SIZE - 4;
    }
    return (uint32_t)m;
}

static int ss_send_pdu(sodchan_ctx_t *ctx, const uint8_t *plain, size_t plain_len)
{
    /* AUTH PDUs are small; stack buffer sized for typical + margin. */
    uint8_t ct[2048];
    unsigned long long clen = 0;
    uint8_t frame[4 + 2048];
    size_t flen = 0;
    int rc;

    if (!ctx->ss_push_ready || !plain || plain_len == 0) {
        return SODCHAN_ERR_STATE;
    }
    if (plain_len + crypto_secretstream_xchacha20poly1305_ABYTES > sizeof(ct)) {
        return SODCHAN_ERR_FULL;
    }
    if (crypto_secretstream_xchacha20poly1305_push(
            &ctx->ss_push, ct, &clen, plain, plain_len, NULL, 0,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    rc = sodchan_wire_frame_encode_max(ct, (size_t)clen, ss_frame_max_body(ctx),
                                       frame, sizeof(frame), &flen);
    if (rc != SODCHAN_OK) {
        return rc;
    }
    return out_append(ctx, frame, flen);
}

static int client_send_auth_device(sodchan_ctx_t *ctx)
{
    uint8_t t_auth[512];
    size_t t_auth_len = 0;
    uint8_t sig[64];
    uint8_t pdu[512];
    size_t pdu_len = 0;
    const char *user;
    const char *dev;
    size_t ulen, dlen;

    if (ctx->role != SODCHAN_ROLE_CLIENT || ctx->auth_sent) {
        return SODCHAN_OK;
    }
    if (!ctx->have_client_id_sk || !ctx->have_client_id_pk || !ctx->have_t_hello) {
        return SODCHAN_OK; /* host may not have device key yet */
    }

    user = ctx->client_username ? ctx->client_username : "";
    dev = ctx->client_device_id ? ctx->client_device_id : "";
    ulen = strlen(user);
    dlen = strlen(dev);
    if (ulen > SODCHAN_USER_MAX) {
        ulen = SODCHAN_USER_MAX;
    }
    if (dlen > SODCHAN_DEVICE_ID_MAX) {
        dlen = SODCHAN_DEVICE_ID_MAX;
    }

    if (sodchan_wire_build_t_auth(ctx->t_hello, ctx->client_id_pk, user, ulen,
                                  dev, dlen, t_auth, sizeof(t_auth),
                                  &t_auth_len) != SODCHAN_OK) {
        return SODCHAN_ERR_PROTOCOL;
    }
    if (crypto_sign_detached(sig, NULL, t_auth, t_auth_len,
                             ctx->client_id_sk) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }
    if (sodchan_wire_auth_device_encode(ctx->client_id_pk, sig, user, ulen, dev,
                                        dlen, pdu, sizeof(pdu),
                                        &pdu_len) != SODCHAN_OK) {
        return SODCHAN_ERR_PROTOCOL;
    }
    if (ss_send_pdu(ctx, pdu, pdu_len) != SODCHAN_OK) {
        return SODCHAN_ERR_FULL;
    }
    ctx->auth_sent = 1;
    return SODCHAN_OK;
}

static int server_send_auth_fail(sodchan_ctx_t *ctx)
{
    uint8_t pdu[8];
    size_t plen = 0;

    if (sodchan_wire_auth_fail_encode(pdu, sizeof(pdu), &plen) != SODCHAN_OK) {
        return SODCHAN_ERR_PROTOCOL;
    }
    return ss_send_pdu(ctx, pdu, plen);
}

static int server_send_auth_ok(sodchan_ctx_t *ctx, const uint8_t *claims,
                               size_t claims_len)
{
    uint8_t pdu[3 + SODCHAN_CLAIMS_MAX];
    size_t plen = 0;

    if (sodchan_wire_auth_ok_encode(claims, claims_len, pdu, sizeof(pdu),
                                    &plen) != SODCHAN_OK) {
        return SODCHAN_ERR_PARAM;
    }
    return ss_send_pdu(ctx, pdu, plen);
}

static int handle_auth_device_pdu(sodchan_ctx_t *ctx, const uint8_t *plain,
                                  size_t plain_len)
{
    uint8_t client_pk[32], sig[64];
    char user[SODCHAN_USER_MAX + 1];
    char device[SODCHAN_DEVICE_ID_MAX + 1];
    size_t ulen = 0, dlen = 0;
    uint8_t t_auth[512];
    size_t t_auth_len = 0;
    sodchan_event_t ev;

    if (ctx->role != SODCHAN_ROLE_SERVER) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "AUTH_DEVICE to client");
        return -1;
    }
    if (ctx->auth_awaiting_decide || ctx->auth_complete || ctx->auth_decided) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "duplicate AUTH_DEVICE");
        return -1;
    }
    if (!ctx->have_t_hello) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_STATE, "missing t_hello");
        return -1;
    }

    if (sodchan_wire_auth_device_decode(plain, plain_len, client_pk, sig, user,
                                        sizeof(user), &ulen, device,
                                        sizeof(device), &dlen) != SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "AUTH_DEVICE decode");
        return -1;
    }

    if (sodchan_wire_build_t_auth(ctx->t_hello, client_pk, user, ulen, device,
                                  dlen, t_auth, sizeof(t_auth),
                                  &t_auth_len) != SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "t_auth build");
        return -1;
    }

    if (crypto_sign_verify_detached(sig, t_auth, t_auth_len, client_pk) != 0) {
        /* Bad sig: AUTH_FAIL on wire, local AUTH_FAILED, no auth_decide */
        (void)server_send_auth_fail(ctx);
        emit_auth_failed(ctx, SODCHAN_AUTH_REASON_BAD_SIG, "bad device sig");
        sodchan_i_set_error(ctx, SODCHAN_ERR_CRYPTO, "AUTH_DEVICE bad signature");
        return -1;
    }

    memcpy(ctx->peer_id_pk, client_pk, 32);
    ctx->have_peer_id = 1;

    memset(&ev, 0, sizeof(ev));
    ev.type = SODCHAN_EVENT_AUTH_DEVICE;
    memcpy(ev.u.auth.peer_id_pk, client_pk, 32);
    snprintf(ev.u.auth.username, sizeof(ev.u.auth.username), "%s", user);
    snprintf(ev.u.auth.device_id, sizeof(ev.u.auth.device_id), "%s", device);
    ev.u.auth.sig_ok = 1;
    (void)sodchan_pubkey_fingerprint_sha256(client_pk, ev.u.auth.fingerprint_sha256,
                                            sizeof(ev.u.auth.fingerprint_sha256));
    (void)sodchan_i_queue_event(ctx, &ev);

    ctx->auth_awaiting_decide = 1;
    return 0;
}

static int handle_auth_ok_pdu(sodchan_ctx_t *ctx, const uint8_t *plain,
                              size_t plain_len)
{
    const uint8_t *claims = NULL;
    size_t claims_len = 0;

    if (ctx->role != SODCHAN_ROLE_CLIENT) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "AUTH_OK to server");
        return -1;
    }
    if (sodchan_wire_auth_ok_decode(plain, plain_len, &claims, &claims_len) !=
        SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "AUTH_OK decode");
        return -1;
    }
    (void)claims;
    (void)claims_len;
    ctx->auth_complete = 1;
    ctx->state = SODCHAN_STATE_READY;
    emit_authenticated(ctx);
    return 0;
}

static int handle_auth_fail_pdu(sodchan_ctx_t *ctx, const uint8_t *plain,
                                size_t plain_len)
{
    uint8_t reason = 0, msg_len = 0;

    if (sodchan_wire_auth_fail_decode(plain, plain_len, &reason, &msg_len) !=
        SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "AUTH_FAIL decode");
        return -1;
    }
    (void)reason; /* wire is always UNSPEC */
    (void)msg_len;
    emit_auth_failed(ctx, SODCHAN_AUTH_REASON_UNSPEC, "AUTH_FAIL received");
    sodchan_i_set_error(ctx, SODCHAN_ERR_REJECTED, "authentication failed");
    return -1;
}

static int handle_encrypted_pdu(sodchan_ctx_t *ctx, const uint8_t *ct, size_t ct_len)
{
    uint8_t plain[2048];
    unsigned long long plen = 0;
    unsigned char tag = 0;
    uint8_t ptype = 0;

    if (!ctx->ss_pull_ready) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_STATE, "ss pull not ready");
        return -1;
    }
    if (ct_len < crypto_secretstream_xchacha20poly1305_ABYTES ||
        ct_len - crypto_secretstream_xchacha20poly1305_ABYTES > sizeof(plain)) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "ss ciphertext size");
        return -1;
    }
    if (crypto_secretstream_xchacha20poly1305_pull(
            &ctx->ss_pull, plain, &plen, &tag, ct, ct_len, NULL, 0) != 0) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_CRYPTO, "ss decrypt failed");
        return -1;
    }
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "unexpected TAG_FINAL");
        return -1;
    }
    if (plen == 0) {
        return 0; /* rekey empty etc. */
    }
    if (sodchan_wire_pdu_type(plain, (size_t)plen, &ptype) != SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "empty pdu");
        return -1;
    }

    if (ctx->state == SODCHAN_STATE_AUTH) {
        switch (ptype) {
        case SODCHAN_PDU_AUTH_DEVICE:
            return handle_auth_device_pdu(ctx, plain, (size_t)plen);
        case SODCHAN_PDU_AUTH_OK:
            return handle_auth_ok_pdu(ctx, plain, (size_t)plen);
        case SODCHAN_PDU_AUTH_FAIL:
            return handle_auth_fail_pdu(ctx, plain, (size_t)plen);
        default:
            sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL,
                                "unexpected pdu in AUTH");
            return -1;
        }
    }

    /* READY mux: PR-6 */
    sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "mux not implemented");
    return -1;
}

static int handle_peer_hello(sodchan_ctx_t *ctx, const uint8_t *body, size_t len)
{
    sodchan_hello_t h;
    int rc;

    rc = sodchan_wire_hello_decode(body, len, &h);
    if (rc != SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "hello decode failed");
        return -1;
    }

    if (ctx->role == SODCHAN_ROLE_CLIENT) {
        uint8_t t_hello[SODCHAN_T_HELLO_LEN];

        if (h.role != SODCHAN_ROLE_SERVER) {
            sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL,
                                "expected server HELLO");
            return -1;
        }

        /* K7 pin fail-closed */
        if (!ctx->accept_any_server_pk) {
            if (!ctx->have_server_id_pk ||
                sodium_memcmp(h.id_pk, ctx->server_id_pk,
                              SODCHAN_PUBKEY_BYTES) != 0) {
                sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL,
                                    "server pin mismatch");
                return -1;
            }
        } else {
            /* Trust advertised pk only after sig verifies (tests). */
            memcpy(ctx->server_id_pk, h.id_pk, SODCHAN_PUBKEY_BYTES);
            ctx->have_server_id_pk = 1;
        }

        memcpy(ctx->peer_eph_pk, h.eph_pk, 32);
        memcpy(ctx->peer_id_pk, h.id_pk, 32);
        ctx->have_peer_eph = 1;
        ctx->have_peer_id = 1;

        if (sodchan_wire_build_t_hello(SODCHAN_PROTO_VERSION, SODCHAN_SUITE_V1,
                                       ctx->eph_pk, ctx->peer_eph_pk,
                                       ctx->peer_id_pk,
                                       t_hello) != SODCHAN_OK) {
            sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "t_hello build");
            return -1;
        }
        memcpy(ctx->t_hello, t_hello, SODCHAN_T_HELLO_LEN);
        ctx->have_t_hello = 1;

        /* K16: verify server signature before any KX trust */
        if (crypto_sign_verify_detached(h.id_sig, t_hello, SODCHAN_T_HELLO_LEN,
                                        ctx->peer_id_pk) != 0) {
            sodchan_i_set_error(ctx, SODCHAN_ERR_CRYPTO,
                                "server HELLO signature invalid");
            return -1;
        }

        emit_hello_received(ctx);

        if (derive_ss_keys_client(ctx) != SODCHAN_OK) {
            sodchan_i_set_error(ctx, SODCHAN_ERR_CRYPTO, "kx client failed");
            return -1;
        }

        if (client_send_ss_header_c2s(ctx) != SODCHAN_OK) {
            sodchan_i_set_error(ctx, SODCHAN_ERR_FULL, "ss header c2s enqueue");
            return -1;
        }

        ctx->state = SODCHAN_STATE_SS_HEADER;
        ctx->hs = SODCHAN_HS_WAIT_PEER_SS;
        return 0;
    }

    /* SERVER receives client HELLO */
    if (h.role != SODCHAN_ROLE_CLIENT) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "expected client HELLO");
        return -1;
    }

    memcpy(ctx->peer_eph_pk, h.eph_pk, 32);
    ctx->have_peer_eph = 1;
    if (sodium_is_zero(h.id_pk, 32) == 0) {
        memcpy(ctx->peer_id_pk, h.id_pk, 32);
        ctx->have_peer_id = 1;
    }

    emit_hello_received(ctx);

    if (queue_local_hello(ctx) != SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_CRYPTO, "server HELLO send");
        return -1;
    }

    if (derive_ss_keys_server(ctx) != SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_CRYPTO, "kx server failed");
        return -1;
    }

    ctx->state = SODCHAN_STATE_SS_HEADER;
    ctx->hs = SODCHAN_HS_WAIT_PEER_SS;
    return 0;
}

static int handle_peer_ss_header(sodchan_ctx_t *ctx, const uint8_t *body,
                                 size_t len)
{
    if (len != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "bad ss header length");
        return -1;
    }

    if (ctx->role == SODCHAN_ROLE_CLIENT) {
        /* Pull s2c with peer header */
        if (crypto_secretstream_xchacha20poly1305_init_pull(
                &ctx->ss_pull, body, ctx->ss_key_s2c) != 0) {
            sodchan_i_set_error(ctx, SODCHAN_ERR_CRYPTO, "ss pull s2c failed");
            return -1;
        }
        ctx->ss_pull_ready = 1;
        ctx->hs = SODCHAN_HS_DONE;
        ctx->state = SODCHAN_STATE_AUTH;
        emit_kx_complete(ctx);
        if (client_send_auth_device(ctx) != SODCHAN_OK) {
            sodchan_i_set_error(ctx, SODCHAN_ERR_CRYPTO, "AUTH_DEVICE send");
            return -1;
        }
        return 0;
    }

    /* SERVER: pull c2s, then push s2c header */
    if (crypto_secretstream_xchacha20poly1305_init_pull(
            &ctx->ss_pull, body, ctx->ss_key_c2s) != 0) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_CRYPTO, "ss pull c2s failed");
        return -1;
    }
    ctx->ss_pull_ready = 1;

    if (server_send_ss_header_s2c(ctx) != SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_FULL, "ss header s2c enqueue");
        return -1;
    }

    ctx->hs = SODCHAN_HS_DONE;
    ctx->state = SODCHAN_STATE_AUTH;
    emit_kx_complete(ctx);
    return 0;
}

static void process_input(sodchan_ctx_t *ctx)
{
    while (ctx->state != SODCHAN_STATE_ERROR &&
           ctx->state != SODCHAN_STATE_CLOSED) {
        size_t consumed = 0;
        const uint8_t *body = NULL;
        size_t body_len = 0;
        int rc;
        int encrypted = (ctx->hs == SODCHAN_HS_DONE);

        /* Mux channel data in READY is PR-6. */
        if (ctx->state == SODCHAN_STATE_READY) {
            return;
        }

        if (ctx->in_len < 4) {
            return;
        }

        if (encrypted) {
            rc = sodchan_wire_frame_parse_max(ctx->in_buf, ctx->in_len,
                                              ss_frame_max_body(ctx), &consumed,
                                              &body, &body_len);
        } else {
            rc = sodchan_wire_frame_parse(ctx->in_buf, ctx->in_len, &consumed,
                                          &body, &body_len);
        }
        if (rc == SODCHAN_ERR_FULL) {
            return; /* need more */
        }
        if (rc != SODCHAN_OK) {
            sodchan_i_set_error(ctx, SODCHAN_ERR_PROTOCOL, "frame parse error");
            return;
        }

        if (ctx->hs == SODCHAN_HS_WAIT_PEER_HELLO) {
            if (handle_peer_hello(ctx, body, body_len) != 0) {
                return;
            }
        } else if (ctx->hs == SODCHAN_HS_WAIT_PEER_SS) {
            if (handle_peer_ss_header(ctx, body, body_len) != 0) {
                return;
            }
        } else if (ctx->hs == SODCHAN_HS_DONE) {
            if (handle_encrypted_pdu(ctx, body, body_len) != 0) {
                return;
            }
        } else {
            sodchan_i_set_error(ctx, SODCHAN_ERR_STATE, "bad hs state");
            return;
        }

        memmove(ctx->in_buf, ctx->in_buf + consumed, ctx->in_len - consumed);
        ctx->in_len -= consumed;

        /* READY: stop processing until PR-6 mux handlers exist */
        if (ctx->state == SODCHAN_STATE_READY && ctx->in_len == 0) {
            return;
        }
    }
}

static int handshake_start(sodchan_ctx_t *ctx)
{
    if (crypto_kx_keypair(ctx->eph_pk, ctx->eph_sk) != 0) {
        return SODCHAN_ERR_CRYPTO;
    }

    if (ctx->role == SODCHAN_ROLE_CLIENT) {
        if (queue_local_hello(ctx) != SODCHAN_OK) {
            return SODCHAN_ERR_FULL;
        }
        ctx->state = SODCHAN_STATE_HELLO;
        ctx->hs = SODCHAN_HS_WAIT_PEER_HELLO;
    } else {
        /* Server waits for client HELLO before sending signed HELLO. */
        ctx->state = SODCHAN_STATE_HELLO;
        ctx->hs = SODCHAN_HS_WAIT_PEER_HELLO;
    }
    return SODCHAN_OK;
}

sodchan_ctx_t *sodchan_create(sodchan_role_t role, const sodchan_config_t *cfg)
{
    sodchan_ctx_t *ctx;
    sodchan_config_t zero;

    if (role != SODCHAN_ROLE_SERVER && role != SODCHAN_ROLE_CLIENT) {
        return NULL;
    }
    if (!cfg) {
        memset(&zero, 0, sizeof(zero));
        cfg = &zero;
    }

#ifndef SODCHAN_ALLOW_LAB_CLEARTEXT
    if (cfg->lab_mode) {
        return NULL;
    }
#endif

    if (role == SODCHAN_ROLE_SERVER) {
        if (!cfg->server_id_pk || !cfg->server_id_sk) {
            return NULL;
        }
    } else {
        if (!cfg->accept_any_server_pk && !cfg->server_id_pk) {
            return NULL;
        }
    }

    if (sodchan_crypto_init() != SODCHAN_OK) {
        return NULL;
    }

    ctx = (sodchan_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) {
        return NULL;
    }

    ctx->role = role;
    apply_config_defaults(ctx, cfg);

    ctx->event_cap = ctx->event_queue_size;
    if (ctx->event_cap == 0) {
        ctx->event_cap = SODCHAN_DEFAULT_EVENT_QUEUE;
    }
    ctx->events = (sodchan_event_t *)calloc(ctx->event_cap,
                                            sizeof(sodchan_event_t));
    if (!ctx->events) {
        free(ctx);
        return NULL;
    }

    if (handshake_start(ctx) != SODCHAN_OK) {
        free(ctx->events);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void sodchan_destroy(sodchan_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    sodium_memzero(ctx->eph_sk, sizeof(ctx->eph_sk));
    sodium_memzero(ctx->client_id_sk, sizeof(ctx->client_id_sk));
    sodium_memzero(ctx->server_id_sk, sizeof(ctx->server_id_sk));
    sodium_memzero(ctx->ss_key_c2s, sizeof(ctx->ss_key_c2s));
    sodium_memzero(ctx->ss_key_s2c, sizeof(ctx->ss_key_s2c));
    free(ctx->events);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

void sodchan_reset(sodchan_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    sodium_memzero(ctx->eph_sk, sizeof(ctx->eph_sk));
    sodium_memzero(ctx->ss_key_c2s, sizeof(ctx->ss_key_c2s));
    sodium_memzero(ctx->ss_key_s2c, sizeof(ctx->ss_key_s2c));
    ctx->have_peer_eph = 0;
    ctx->have_peer_id = 0;
    ctx->have_t_hello = 0;
    ctx->ss_push_ready = 0;
    ctx->ss_pull_ready = 0;
    ctx->auth_sent = 0;
    ctx->auth_awaiting_decide = 0;
    ctx->auth_decided = 0;
    ctx->auth_complete = 0;
    ctx->error = 0;
    ctx->error_msg[0] = '\0';
    ctx->event_head = 0;
    ctx->event_count = 0;
    ctx->out_len = 0;
    ctx->out_off = 0;
    ctx->in_len = 0;
    if (ctx->events) {
        memset(ctx->events, 0, ctx->event_cap * sizeof(sodchan_event_t));
    }
    (void)handshake_start(ctx);
}

size_t sodchan_feed_input(sodchan_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t take;

    if (!ctx || !data || len == 0) {
        return 0;
    }
    if (ctx->state == SODCHAN_STATE_ERROR || ctx->state == SODCHAN_STATE_CLOSED) {
        return 0;
    }

    take = len;
    if (take > sizeof(ctx->in_buf) - ctx->in_len) {
        take = sizeof(ctx->in_buf) - ctx->in_len;
    }
    if (take == 0) {
        return 0;
    }
    memcpy(ctx->in_buf + ctx->in_len, data, take);
    ctx->in_len += take;
    process_input(ctx);
    return take;
}

size_t sodchan_get_output(sodchan_ctx_t *ctx, uint8_t *buf, size_t max_len)
{
    size_t n;

    if (!ctx || !buf || max_len == 0) {
        return 0;
    }
    if (ctx->out_off >= ctx->out_len) {
        return 0;
    }
    n = ctx->out_len - ctx->out_off;
    if (n > max_len) {
        n = max_len;
    }
    memcpy(buf, ctx->out_buf + ctx->out_off, n);
    ctx->out_off += n;
    if (ctx->out_off >= ctx->out_len) {
        ctx->out_off = 0;
        ctx->out_len = 0;
    }
    return n;
}

int sodchan_next_event(sodchan_ctx_t *ctx, sodchan_event_t *ev)
{
    if (!ctx || !ev) {
        return 0;
    }
    if (ctx->event_count == 0) {
        return 0;
    }
    *ev = ctx->events[ctx->event_head];
    ctx->event_head = (ctx->event_head + 1) % ctx->event_cap;
    ctx->event_count--;
    return 1;
}

sodchan_state_t sodchan_current_state(const sodchan_ctx_t *ctx)
{
    if (!ctx) {
        return SODCHAN_STATE_ERROR;
    }
    return ctx->state;
}

int sodchan_auth_decide_ex(sodchan_ctx_t *ctx, int accept,
                           const uint8_t *claims, size_t claims_len)
{
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    if (ctx->role != SODCHAN_ROLE_SERVER) {
        return SODCHAN_ERR_STATE;
    }
    if (!ctx->auth_awaiting_decide || ctx->auth_decided) {
        return SODCHAN_ERR_STATE;
    }
    if (ctx->state != SODCHAN_STATE_AUTH) {
        return SODCHAN_ERR_STATE;
    }
    if (claims_len > 0 && !claims) {
        return SODCHAN_ERR_PARAM;
    }
    if (claims_len > SODCHAN_CLAIMS_MAX) {
        return SODCHAN_ERR_PARAM;
    }

    ctx->auth_awaiting_decide = 0;
    ctx->auth_decided = 1;

    if (accept) {
        if (server_send_auth_ok(ctx, claims, claims_len) != SODCHAN_OK) {
            sodchan_i_set_error(ctx, SODCHAN_ERR_FULL, "AUTH_OK send");
            return SODCHAN_ERR_FULL;
        }
        ctx->auth_complete = 1;
        ctx->state = SODCHAN_STATE_READY;
        emit_authenticated(ctx);
        return SODCHAN_OK;
    }

    if (server_send_auth_fail(ctx) != SODCHAN_OK) {
        sodchan_i_set_error(ctx, SODCHAN_ERR_FULL, "AUTH_FAIL send");
        return SODCHAN_ERR_FULL;
    }
    emit_auth_failed(ctx, SODCHAN_AUTH_REASON_POLICY, "auth_decide reject");
    sodchan_i_set_error(ctx, SODCHAN_ERR_REJECTED, "authentication rejected");
    return SODCHAN_OK;
}

int sodchan_auth_decide(sodchan_ctx_t *ctx, int accept)
{
    return sodchan_auth_decide_ex(ctx, accept, NULL, 0);
}

int sodchan_channel_open(sodchan_ctx_t *ctx, const char *name,
                         uint32_t *local_id_out)
{
    (void)name;
    (void)local_id_out;
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    return SODCHAN_ERR_STATE;
}

int sodchan_channel_accept(sodchan_ctx_t *ctx, uint32_t local_id, int accept)
{
    (void)local_id;
    (void)accept;
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    return SODCHAN_ERR_STATE;
}

int sodchan_channel_send(sodchan_ctx_t *ctx, uint32_t local_id,
                         const uint8_t *data, size_t len)
{
    (void)local_id;
    (void)data;
    (void)len;
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    return SODCHAN_ERR_STATE;
}

uint32_t sodchan_channel_window_avail(const sodchan_ctx_t *ctx,
                                      uint32_t local_id)
{
    (void)local_id;
    if (!ctx) {
        return 0;
    }
    return 0;
}

int sodchan_channel_eof(sodchan_ctx_t *ctx, uint32_t local_id)
{
    (void)local_id;
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    return SODCHAN_ERR_STATE;
}

int sodchan_channel_close(sodchan_ctx_t *ctx, uint32_t local_id)
{
    (void)local_id;
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    return SODCHAN_ERR_STATE;
}

int sodchan_channel_window_adjust(sodchan_ctx_t *ctx, uint32_t local_id,
                                  uint32_t credit)
{
    (void)local_id;
    (void)credit;
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    return SODCHAN_ERR_STATE;
}

int sodchan_disconnect(sodchan_ctx_t *ctx, int reason, const char *msg)
{
    (void)reason;
    (void)msg;
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    if (ctx->state == SODCHAN_STATE_CLOSED) {
        return SODCHAN_OK;
    }
    ctx->state = SODCHAN_STATE_CLOSED;
    return SODCHAN_OK;
}
