/**
 * @file sodchan_internal.h
 * @brief Internal context and helpers for libsodchan (not installed).
 */

#ifndef SODCHAN_INTERNAL_H
#define SODCHAN_INTERNAL_H

#include "sodchan.h"
#include "sodchan_wire.h"

#include <stddef.h>
#include <stdint.h>

#include <sodium.h>

#define SODCHAN_DEFAULT_EVENT_QUEUE   16
#define SODCHAN_DEFAULT_MAX_RECORD    (256u * 1024u)
#define SODCHAN_DEFAULT_MAX_CHANNEL   (256u * 1024u)
#define SODCHAN_DEFAULT_MAX_CHANNELS  SODCHAN_MAX_CHANNELS
#define SODCHAN_DEFAULT_INIT_WINDOW   (256u * 1024u)
#define SODCHAN_DEFAULT_MAX_PACKET    (64u * 1024u)

#define SODCHAN_CFG_STORE_SIZE        1024
#define SODCHAN_OUT_BUF_SIZE          (64u * 1024u)
#define SODCHAN_IN_BUF_SIZE           (64u * 1024u)

/* Handshake sub-progress (public state is HELLO / SS_HEADER / AUTH). */
typedef enum {
    SODCHAN_HS_START = 0,       /* local HELLO not yet prepared (server wait) */
    SODCHAN_HS_WAIT_PEER_HELLO, /* local HELLO sent or server waiting */
    SODCHAN_HS_WAIT_PEER_SS,    /* need peer secretstream header */
    SODCHAN_HS_DONE             /* both SS headers done → AUTH */
} sodchan_hs_t;

struct sodchan_ctx {
    sodchan_role_t  role;
    sodchan_state_t state;
    sodchan_hs_t    hs;
    int             error;
    char            error_msg[SODCHAN_ERROR_MAX];

    size_t   event_queue_size;
    size_t   max_record_size;
    size_t   max_channel_data;
    size_t   max_channels;
    uint32_t initial_window;
    uint32_t max_packet;
    int      accept_any_server_pk;
    int      lab_mode;

    uint8_t client_id_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t client_id_sk[SODCHAN_SECKEY_BYTES];
    uint8_t server_id_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t server_id_sk[SODCHAN_SECKEY_BYTES];
    int     have_client_id_pk;
    int     have_client_id_sk;
    int     have_server_id_pk;
    int     have_server_id_sk;

    /* Ephemeral KX (X25519 crypto_kx) */
    uint8_t eph_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t eph_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t peer_eph_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t peer_id_pk[SODCHAN_PUBKEY_BYTES];
    int     have_peer_eph;
    int     have_peer_id;

    uint8_t ss_key_c2s[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    uint8_t ss_key_s2c[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    crypto_secretstream_xchacha20poly1305_state ss_push;
    crypto_secretstream_xchacha20poly1305_state ss_pull;
    int ss_push_ready;
    int ss_pull_ready;

    /* Transcript for AUTH_DEVICE (same bytes as server HELLO sig). */
    uint8_t t_hello[SODCHAN_T_HELLO_LEN];
    int     have_t_hello;

    /* AUTH phase (PR-5) */
    int auth_sent;              /* CLIENT: AUTH_DEVICE queued */
    int auth_awaiting_decide;   /* SERVER: sig ok, waiting auth_decide */
    int auth_decided;           /* SERVER: decide already called */
    int auth_complete;          /* both: session authenticated */

    char cfg_store[SODCHAN_CFG_STORE_SIZE];
    size_t cfg_store_used;
    char *allowed_channels;
    char *client_username;
    char *client_device_id;

    uint8_t out_buf[SODCHAN_OUT_BUF_SIZE];
    size_t  out_len;
    size_t  out_off;

    uint8_t in_buf[SODCHAN_IN_BUF_SIZE];
    size_t  in_len;

    sodchan_event_t *events;
    size_t event_cap;
    size_t event_head;
    size_t event_count;
};

void sodchan_i_set_error(sodchan_ctx_t *ctx, int code, const char *fmt, ...);
int  sodchan_i_queue_event(sodchan_ctx_t *ctx, const sodchan_event_t *ev);

/** Ensure sodium_init(); SODCHAN_OK or SODCHAN_ERR_CRYPTO. */
int sodchan_crypto_init(void);

/**
 * Labeled session key for secretstream (ADR 014 / design §4.3.1).
 * ss_key = BLAKE2b-32(kx_direction_key || dom)
 */
int sodchan_crypto_ss_key_derive(const uint8_t kx_key[32],
                                 const char *dom,
                                 uint8_t out_key[32]);

#endif /* SODCHAN_INTERNAL_H */
