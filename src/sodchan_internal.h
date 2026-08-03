/**
 * @file sodchan_internal.h
 * @brief Internal context and helpers for libsodchan (not installed).
 */

#ifndef SODCHAN_INTERNAL_H
#define SODCHAN_INTERNAL_H

#include "sodchan.h"

#include <stddef.h>
#include <stdint.h>

#define SODCHAN_DEFAULT_EVENT_QUEUE   16
#define SODCHAN_DEFAULT_MAX_RECORD    (256u * 1024u)
#define SODCHAN_DEFAULT_MAX_CHANNEL   (256u * 1024u)
#define SODCHAN_DEFAULT_MAX_CHANNELS  SODCHAN_MAX_CHANNELS
#define SODCHAN_DEFAULT_INIT_WINDOW   (256u * 1024u)
#define SODCHAN_DEFAULT_MAX_PACKET    (64u * 1024u)

#define SODCHAN_CFG_STORE_SIZE        1024
#define SODCHAN_OUT_BUF_SIZE          (64u * 1024u)
#define SODCHAN_IN_BUF_SIZE           (64u * 1024u)

struct sodchan_ctx {
    sodchan_role_t  role;
    sodchan_state_t state;
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

    char cfg_store[SODCHAN_CFG_STORE_SIZE];
    size_t cfg_store_used;
    char *allowed_channels;
    char *client_username;
    char *client_device_id;

    /* Scaffold I/O buffers (PR-1 empty; filled by later PRs). */
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

#endif /* SODCHAN_INTERNAL_H */
