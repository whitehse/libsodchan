/**
 * @file sodchan.h
 * @brief libsodium multiplexed channel transport — pure plumbing API.
 *
 * System-call free, callback free. Caller owns sockets, TLS, and policy.
 *
 * Replaces libchssh for CPE agent call-home and mobile control plane.
 * Does NOT replace libchssh for E7 / NETCONF Call Home (OpenSSH interop).
 *
 * Roles:
 *   SODCHAN_ROLE_SERVER — edgehost after accept (raw :4336 or TLS-unwrapped :4337)
 *   SODCHAN_ROLE_CLIENT — cpe_agent or mobile app
 *
 * Progress is pull-driven:
 *   sodchan_feed_input / sodchan_get_output / sodchan_next_event
 */

#ifndef SODCHAN_H
#define SODCHAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SODCHAN_VERSION_MAJOR 0
#define SODCHAN_VERSION_MINOR 5
#define SODCHAN_VERSION_PATCH 0

/* Internal AUTH_FAIL reasons (event u.error.code / metrics; wire always UNSPEC). */
#define SODCHAN_AUTH_REASON_UNSPEC       0
#define SODCHAN_AUTH_REASON_BAD_SIG      1
#define SODCHAN_AUTH_REASON_UNKNOWN_KEY  2
#define SODCHAN_AUTH_REASON_REVOKED      3
#define SODCHAN_AUTH_REASON_POLICY       4
#define SODCHAN_AUTH_REASON_PROTOCOL     5

#define SODCHAN_MAX_CHANNELS       16
#define SODCHAN_PUBKEY_BYTES       32
#define SODCHAN_SECKEY_BYTES       64
#define SODCHAN_SEED_BYTES         32
/** On-disk seed blob: magic "SCSK\\x01" (5 bytes) + 32-byte seed. */
#define SODCHAN_SEED_BLOB_LEN      37
#define SODCHAN_CHANNEL_NAME_MAX   63
#define SODCHAN_DATA_MAX           (64 * 1024)
#define SODCHAN_ERROR_MAX          256
#define SODCHAN_USER_MAX           128
#define SODCHAN_DEVICE_ID_MAX      128
/** "SHA256:" + unpadded base64(SHA-256(pk)) + NUL — plenty of room. */
#define SODCHAN_FP_SHA256_MAX      96
#define SODCHAN_CLAIMS_MAX         1024

/* Domain separation for session KDF (ADR 014; used from PR-4 handshake). */
#define SODCHAN_DOM_SS_C2S         "sodchan-ss-c2s-v1"
#define SODCHAN_DOM_SS_S2C         "sodchan-ss-s2c-v1"

/* CPE / product channel names (match libchssh subsystem strings). */
#define SODCHAN_CHANNEL_EDGE_TELEMETRY "edge-telemetry"
#define SODCHAN_CHANNEL_EDGE_PG        "edge-pg"
#define SODCHAN_CHANNEL_EDGE_AI        "edge-ai"
#define SODCHAN_CHANNEL_EDGE_CONTROL   "edge-control"
#define SODCHAN_CHANNEL_EDGE_USP       "edge-usp"
#define SODCHAN_CHANNEL_MOBILE_CONTROL "mobile-control"
#define SODCHAN_CHANNEL_SFTP           "sftp"
#define SODCHAN_CHANNEL_TUN            "tun"
#define SODCHAN_CHANNEL_TAP            "tap"
#define SODCHAN_CHANNEL_SHELL          "shell"

/* Return codes (negative = error class) */
#define SODCHAN_OK                 0
#define SODCHAN_ERR_PARAM         -1
#define SODCHAN_ERR_STATE         -2
#define SODCHAN_ERR_NOMEM         -3
#define SODCHAN_ERR_CRYPTO        -4
#define SODCHAN_ERR_PROTOCOL      -5
#define SODCHAN_ERR_WINDOW        -6   /* peer window exhausted */
#define SODCHAN_ERR_FULL          -7   /* output or event queue full */
#define SODCHAN_ERR_NOTFOUND      -8
#define SODCHAN_ERR_REJECTED      -9

typedef enum {
    SODCHAN_ROLE_SERVER = 0,
    SODCHAN_ROLE_CLIENT = 1
} sodchan_role_t;

typedef struct {
    size_t event_queue_size;     /* 0 → 16 */
    size_t max_record_size;      /* 0 → 256 KiB secretstream plaintext */
    size_t max_channel_data;     /* 0 → 256 KiB per-channel buffer budget */
    size_t max_channels;         /* 0 → 16 */
    uint32_t initial_window;     /* 0 → 256 KiB */
    uint32_t max_packet;         /* 0 → 64 KiB CHANNEL_DATA cap */

    const uint8_t *client_id_pk; /* 32; CLIENT */
    const uint8_t *client_id_sk; /* 64; CLIENT required for real auth (PR-5) */
    const uint8_t *server_id_pk; /* 32; SERVER required; CLIENT = pin material */
    const uint8_t *server_id_sk; /* 64; SERVER required */

    /*
     * CLIENT pin polarity (fail-closed; mirrors libchssh accept_any_hostkey):
     *   accept_any_server_pk = 0 (zero-init / field default): pin REQUIRED.
     *     sodchan_create(CLIENT) returns NULL if server_id_pk is NULL.
     *   accept_any_server_pk = 1: tests/lab only.
     * Never set 1 in field CPE/mobile configs.
     */
    int accept_any_server_pk;

    /* SERVER allowlist; NULL → default product list (see docs) */
    const char *allowed_channels;

    const char *client_username; /* advisory, copied into AUTH_DEVICE */
    const char *client_device_id;

    /*
     * Reserved for a future multi-try AUTH on one connection.
     * v1: any AUTH_FAIL closes the session; this field is IGNORED.
     */
    int max_auth_attempts_reserved;

    /*
     * lab_mode: ONLY meaningful if compiled with SODCHAN_ALLOW_LAB_CLEARTEXT.
     * Default builds: sodchan_create returns NULL if lab_mode != 0.
     * Preferred lab path: real sodium + deterministic seeds (lab_mode=0).
     */
    int lab_mode;
} sodchan_config_t;

typedef struct sodchan_ctx sodchan_ctx_t;

typedef enum {
    SODCHAN_STATE_IDLE = 0,
    SODCHAN_STATE_HELLO,
    SODCHAN_STATE_SS_HEADER,
    SODCHAN_STATE_AUTH,
    SODCHAN_STATE_READY,
    SODCHAN_STATE_DRAINING,
    SODCHAN_STATE_CLOSED,
    SODCHAN_STATE_ERROR
} sodchan_state_t;

typedef enum {
    SODCHAN_EVENT_NONE = 0,
    SODCHAN_EVENT_HELLO_RECEIVED,
    SODCHAN_EVENT_KX_COMPLETE,
    SODCHAN_EVENT_AUTH_DEVICE,       /* SERVER: sig verified; decide */
    SODCHAN_EVENT_AUTHENTICATED,
    SODCHAN_EVENT_AUTH_FAILED,
    SODCHAN_EVENT_CHANNEL_OPEN,
    SODCHAN_EVENT_CHANNEL_OPENED,
    SODCHAN_EVENT_CHANNEL_OPEN_FAIL,
    SODCHAN_EVENT_CHANNEL_DATA,
    SODCHAN_EVENT_CHANNEL_WINDOW,
    SODCHAN_EVENT_CHANNEL_EOF,
    SODCHAN_EVENT_CHANNEL_CLOSE,
    SODCHAN_EVENT_PING,
    SODCHAN_EVENT_DISCONNECTED,
    SODCHAN_EVENT_ERROR
} sodchan_event_type_t;

typedef struct {
    sodchan_event_type_t type;
    union {
        struct {
            uint8_t peer_id_pk[SODCHAN_PUBKEY_BYTES];
            char    username[SODCHAN_USER_MAX + 1];
            char    device_id[SODCHAN_DEVICE_ID_MAX + 1];
            char    fingerprint_sha256[SODCHAN_FP_SHA256_MAX];
            int     sig_ok;
        } auth;
        struct {
            uint32_t channel_id;
            uint32_t peer_channel_id;
            char     name[SODCHAN_CHANNEL_NAME_MAX + 1];
            uint32_t init_window;
            uint32_t max_packet;
        } channel;
        struct {
            uint32_t channel_id;
            uint32_t bytes_added;
            uint32_t window_avail;
        } window;
        struct {
            uint32_t channel_id;
            uint8_t  data[SODCHAN_DATA_MAX];
            size_t   len;
        } data;
        struct {
            char message[SODCHAN_ERROR_MAX];
            int  code;
        } error;
    } u;
} sodchan_event_t;

/**
 * Create context.
 * CLIENT: NULL if accept_any_server_pk==0 and server_id_pk==NULL (fail-closed).
 * SERVER: NULL if server_id_pk or server_id_sk missing.
 * lab_mode!=0 without SODCHAN_ALLOW_LAB_CLEARTEXT → NULL.
 */
sodchan_ctx_t *sodchan_create(sodchan_role_t role, const sodchan_config_t *cfg);
void           sodchan_destroy(sodchan_ctx_t *ctx);
void           sodchan_reset(sodchan_ctx_t *ctx);

/**
 * Feed peer bytes. Returns bytes consumed (0..len). Never negative.
 */
size_t sodchan_feed_input(sodchan_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * Drain bytes to write to the socket (or TLS plaintext fd).
 * Returns bytes written to buf (0 if none). Never negative.
 */
size_t sodchan_get_output(sodchan_ctx_t *ctx, uint8_t *buf, size_t max_len);

/** 1 = filled event, 0 = empty. */
int sodchan_next_event(sodchan_ctx_t *ctx, sodchan_event_t *ev);

sodchan_state_t sodchan_current_state(const sodchan_ctx_t *ctx);

/**
 * SERVER: after SODCHAN_EVENT_AUTH_DEVICE only, once.
 * accept=1 → encrypted AUTH_OK (empty claims) + AUTHENTICATED + READY.
 * accept=0 → encrypted AUTH_FAIL (wire UNSPEC) + AUTH_FAILED + ERROR.
 * Second call or wrong state → SODCHAN_ERR_STATE.
 */
int sodchan_auth_decide(sodchan_ctx_t *ctx, int accept);

/**
 * SERVER: same as auth_decide, with optional AUTH_OK claims blob (≤1024).
 * claims may be NULL when claims_len==0.
 */
int sodchan_auth_decide_ex(sodchan_ctx_t *ctx, int accept,
                           const uint8_t *claims, size_t claims_len);

int sodchan_channel_open(sodchan_ctx_t *ctx, const char *name,
                         uint32_t *local_id_out);
int sodchan_channel_accept(sodchan_ctx_t *ctx, uint32_t local_id, int accept);

/**
 * Send on local channel.
 * SODCHAN_OK | ERR_WINDOW | ERR_FULL | ERR_STATE | ERR_PARAM | ERR_NOTFOUND
 */
int sodchan_channel_send(sodchan_ctx_t *ctx, uint32_t local_id,
                         const uint8_t *data, size_t len);

uint32_t sodchan_channel_window_avail(const sodchan_ctx_t *ctx,
                                      uint32_t local_id);

int sodchan_channel_eof(sodchan_ctx_t *ctx, uint32_t local_id);
int sodchan_channel_close(sodchan_ctx_t *ctx, uint32_t local_id);
int sodchan_channel_window_adjust(sodchan_ctx_t *ctx, uint32_t local_id,
                                  uint32_t credit);

int sodchan_disconnect(sodchan_ctx_t *ctx, int reason, const char *msg);

/**
 * Generate a random Ed25519 device/server identity keypair.
 * sk is 64-byte libsodium format (seed||pk layout as crypto_sign defines).
 */
int sodchan_keygen_device(uint8_t pk[SODCHAN_PUBKEY_BYTES],
                          uint8_t sk[SODCHAN_SECKEY_BYTES]);

/** Deterministic keypair from 32-byte seed (crypto_sign_seed_keypair). */
int sodchan_keygen_from_seed(const uint8_t seed[SODCHAN_SEED_BYTES],
                             uint8_t pk[SODCHAN_PUBKEY_BYTES],
                             uint8_t sk[SODCHAN_SECKEY_BYTES]);

/**
 * Pack seed as SCSK\\x01 || seed (37 bytes). Bare 32-byte seed files are
 * rejected by decode to avoid mixed formats (design §4.3.3).
 */
int sodchan_seed_encode(const uint8_t seed[SODCHAN_SEED_BYTES],
                        uint8_t out[SODCHAN_SEED_BLOB_LEN]);

/**
 * Unpack SCSK\\x01 blob. Returns SODCHAN_ERR_PARAM if len/magic wrong
 * (including bare 32-byte buffers).
 */
int sodchan_seed_decode(const uint8_t *blob, size_t len,
                        uint8_t seed[SODCHAN_SEED_BYTES]);

/** Decode SCSK blob then keygen_from_seed. */
int sodchan_keygen_from_seed_blob(const uint8_t *blob, size_t len,
                                  uint8_t pk[SODCHAN_PUBKEY_BYTES],
                                  uint8_t sk[SODCHAN_SECKEY_BYTES]);

/**
 * OpenSSH-style fingerprint: "SHA256:" + unpadded base64 of SHA-256(pk).
 * out_len must be >= SODCHAN_FP_SHA256_MAX (or at least need+1).
 */
int sodchan_pubkey_fingerprint_sha256(const uint8_t pk[SODCHAN_PUBKEY_BYTES],
                                      char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SODCHAN_H */
