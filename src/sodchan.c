/**
 * @file sodchan.c
 * @brief libsodchan core — pure state machine (no sockets).
 *
 * PR-1: create / destroy / reset / plumbing stubs.
 * Handshake, crypto, channels land in later PRs.
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

    if (ctx->events && ctx->event_count < ctx->event_cap) {
        size_t idx = (ctx->event_head + ctx->event_count) % ctx->event_cap;
        memset(&ev, 0, sizeof(ev));
        ev.type = SODCHAN_EVENT_ERROR;
        ev.u.error.code = ctx->error;
        memcpy(ev.u.error.message, ctx->error_msg, sizeof(ev.u.error.message));
        ctx->events[idx] = ev;
        ctx->event_count++;
    }
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
        /* CLIENT fail-closed pin (K7). */
        if (!cfg->accept_any_server_pk && !cfg->server_id_pk) {
            return NULL;
        }
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

    ctx->state = SODCHAN_STATE_IDLE;
    ctx->event_head = 0;
    ctx->event_count = 0;
    ctx->out_len = 0;
    ctx->out_off = 0;
    ctx->in_len = 0;

    return ctx;
}

void sodchan_destroy(sodchan_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    free(ctx->events);
    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
}

void sodchan_reset(sodchan_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    ctx->state = SODCHAN_STATE_IDLE;
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
}

size_t sodchan_feed_input(sodchan_ctx_t *ctx, const uint8_t *data, size_t len)
{
    (void)data;
    if (!ctx || ctx->state == SODCHAN_STATE_ERROR ||
        ctx->state == SODCHAN_STATE_CLOSED) {
        return 0;
    }
    /* PR-1: no handshake yet — consume nothing. */
    (void)len;
    return 0;
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

int sodchan_auth_decide(sodchan_ctx_t *ctx, int accept)
{
    (void)accept;
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    return SODCHAN_ERR_STATE; /* AUTH path not implemented (PR-5) */
}

int sodchan_channel_open(sodchan_ctx_t *ctx, const char *name,
                         uint32_t *local_id_out)
{
    (void)name;
    (void)local_id_out;
    if (!ctx) {
        return SODCHAN_ERR_PARAM;
    }
    return SODCHAN_ERR_STATE; /* PR-6 */
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

/* PR-2 implements real sodium keygen. */
int sodchan_keygen_device(uint8_t pk[SODCHAN_PUBKEY_BYTES],
                          uint8_t sk[SODCHAN_SECKEY_BYTES])
{
    (void)pk;
    (void)sk;
    return SODCHAN_ERR_STATE;
}

int sodchan_keygen_from_seed(const uint8_t seed[32],
                             uint8_t pk[SODCHAN_PUBKEY_BYTES],
                             uint8_t sk[SODCHAN_SECKEY_BYTES])
{
    (void)seed;
    (void)pk;
    (void)sk;
    return SODCHAN_ERR_STATE;
}

int sodchan_pubkey_fingerprint_sha256(const uint8_t pk[SODCHAN_PUBKEY_BYTES],
                                      char *out, size_t out_len)
{
    (void)pk;
    (void)out;
    (void)out_len;
    return SODCHAN_ERR_STATE;
}
