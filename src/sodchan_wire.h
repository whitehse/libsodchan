/**
 * @file sodchan_wire.h
 * @brief Normative wire encode/decode (ADR 017). Not installed publicly.
 */

#ifndef SODCHAN_WIRE_H
#define SODCHAN_WIRE_H

#include "sodchan.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Protocol constants (ADR 017) --- */
#define SODCHAN_PROTO_VERSION       1u
#define SODCHAN_SUITE_V1            1u
#define SODCHAN_MAGIC               0x5343u /* 'S''C' u16be */

#define SODCHAN_EPH_PK_BYTES        32u
#define SODCHAN_ID_PK_BYTES         32u
#define SODCHAN_SIGN_BYTES          64u
#define SODCHAN_SS_HEADER_BYTES     24u
#define SODCHAN_SS_ABYTES           17u

#define SODCHAN_MAX_CLEAR_FRAME     512u
#define SODCHAN_MAX_INNER_PDU       (256u * 1024u)
#define SODCHAN_CLAIMS_MAX          1024u

#define SODCHAN_HELLO_BODY_LEN      140u
#define SODCHAN_DOM_SERVER_HELLO    "sodchan-v1-server-hello"
#define SODCHAN_DOM_CLIENT_AUTH     "sodchan-v1-client-auth"
/* DOM_SS_* also in public sodchan.h */

/* PDU type codes */
#define SODCHAN_PDU_CHANNEL_OPEN         1u
#define SODCHAN_PDU_CHANNEL_OPEN_CONFIRM 2u
#define SODCHAN_PDU_CHANNEL_OPEN_FAIL    3u
#define SODCHAN_PDU_CHANNEL_WINDOW       4u
#define SODCHAN_PDU_CHANNEL_DATA         5u
#define SODCHAN_PDU_CHANNEL_EOF          6u
#define SODCHAN_PDU_CHANNEL_CLOSE        7u
#define SODCHAN_PDU_PING                 8u
#define SODCHAN_PDU_PONG                 9u
#define SODCHAN_PDU_DISCONNECT          10u
#define SODCHAN_PDU_AUTH_DEVICE         20u
#define SODCHAN_PDU_AUTH_OK             21u
#define SODCHAN_PDU_AUTH_FAIL           22u

/* AUTH_FAIL reason codes (wire always UNSPEC in v1) */
#define SODCHAN_AUTH_FAIL_UNSPEC      0u
#define SODCHAN_AUTH_FAIL_BAD_SIG     1u
#define SODCHAN_AUTH_FAIL_UNKNOWN_KEY 2u
#define SODCHAN_AUTH_FAIL_REVOKED     3u
#define SODCHAN_AUTH_FAIL_POLICY      4u
#define SODCHAN_AUTH_FAIL_PROTOCOL    5u

/* Channel open-fail / disconnect reasons */
#define SODCHAN_REASON_UNKNOWN            0u
#define SODCHAN_REASON_ADMIN_PROHIBITED   1u
#define SODCHAN_REASON_CONNECT_FAILED     2u
#define SODCHAN_REASON_UNKNOWN_TYPE       3u
#define SODCHAN_REASON_RESOURCE_SHORTAGE  4u
#define SODCHAN_REASON_AUTH_REQUIRED     10u
#define SODCHAN_REASON_PROTOCOL_ERROR    11u
#define SODCHAN_REASON_BY_APPLICATION    12u

/* --- Integer helpers (big-endian) --- */
void sodchan_wire_put_u16(uint8_t *p, uint16_t v);
void sodchan_wire_put_u32(uint8_t *p, uint32_t v);
uint16_t sodchan_wire_get_u16(const uint8_t *p);
uint32_t sodchan_wire_get_u32(const uint8_t *p);

/* --- Cleartext frame: u32be length | body[L] --- */
/**
 * Encode length-prefixed frame. Writes 4 + body_len bytes.
 * body_len must be 1..SODCHAN_MAX_CLEAR_FRAME for HELLO phase
 * (caller enforces); 0 is illegal for clear frames.
 */
int sodchan_wire_frame_encode(const uint8_t *body, size_t body_len,
                              uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * Parse one complete frame from buffer.
 * Returns SODCHAN_OK and sets *consumed, *body (pointer into data+4), *body_len.
 * Returns 0 bytes needed semantics via ERR_STATE if truncated (need more data):
 *   SODCHAN_ERR_FULL means incomplete (need more input) — used as "want more".
 * Actually: return SODCHAN_ERR_FULL for incomplete, SODCHAN_ERR_PROTOCOL for bad L.
 */
int sodchan_wire_frame_parse(const uint8_t *data, size_t len,
                             size_t *consumed,
                             const uint8_t **body, size_t *body_len);

/* --- HELLO body (fixed 140 bytes) --- */
typedef struct {
    uint16_t proto_version;
    uint16_t suite_id;
    uint16_t role; /* SODCHAN_ROLE_* */
    uint32_t flags;
    uint8_t  eph_pk[SODCHAN_EPH_PK_BYTES];
    uint8_t  id_pk[SODCHAN_ID_PK_BYTES];
    uint8_t  id_sig[SODCHAN_SIGN_BYTES];
} sodchan_hello_t;

int sodchan_wire_hello_encode(const sodchan_hello_t *h,
                              uint8_t *out, size_t out_cap, size_t *out_len);
int sodchan_wire_hello_decode(const uint8_t *body, size_t len,
                              sodchan_hello_t *h);

/*
 * Domain lengths (NUL not included on wire):
 *   "sodchan-v1-server-hello" = 23
 *   "sodchan-v1-client-auth"  = 22
 * Design doc once said 22 for server-hello; the string above is authoritative.
 */
#define SODCHAN_DOM_SERVER_HELLO_LEN 23u
#define SODCHAN_DOM_CLIENT_AUTH_LEN  22u

/**
 * Build T_hello transcript preimage (for server sign / client verify).
 * T_hello = DOM || u16be(proto) || u16be(suite) || client_eph || server_eph || server_id_pk
 * Fixed length: 23 + 2 + 2 + 32 + 32 + 32 = 123.
 */
#define SODCHAN_T_HELLO_LEN 123u
int sodchan_wire_build_t_hello(uint16_t proto_version, uint16_t suite_id,
                               const uint8_t client_eph_pk[32],
                               const uint8_t server_eph_pk[32],
                               const uint8_t server_id_pk[32],
                               uint8_t out[SODCHAN_T_HELLO_LEN]);

/**
 * Build T_auth preimage.
 * T_auth = DOM || T_hello || client_id_pk || u8 ulen || user || u8 dlen || device
 * out_cap must hold 22 + 123 + 32 + 1 + U + 1 + D.
 */
int sodchan_wire_build_t_auth(const uint8_t t_hello[SODCHAN_T_HELLO_LEN],
                              const uint8_t client_id_pk[32],
                              const char *username, size_t username_len,
                              const char *device_id, size_t device_id_len,
                              uint8_t *out, size_t out_cap, size_t *out_len);

/* --- AUTH PDUs --- */
int sodchan_wire_auth_device_encode(const uint8_t client_id_pk[32],
                                    const uint8_t client_sig[64],
                                    const char *username, size_t username_len,
                                    const char *device_id, size_t device_id_len,
                                    uint8_t *out, size_t out_cap, size_t *out_len);

int sodchan_wire_auth_device_decode(const uint8_t *pdu, size_t len,
                                    uint8_t client_id_pk[32],
                                    uint8_t client_sig[64],
                                    char *username, size_t username_cap,
                                    size_t *username_len,
                                    char *device_id, size_t device_id_cap,
                                    size_t *device_id_len);

int sodchan_wire_auth_ok_encode(const uint8_t *claims, size_t claims_len,
                                uint8_t *out, size_t out_cap, size_t *out_len);

int sodchan_wire_auth_ok_decode(const uint8_t *pdu, size_t len,
                                const uint8_t **claims, size_t *claims_len);

/** Always encodes reason=UNSPEC and empty msg on the wire (anti-oracle). */
int sodchan_wire_auth_fail_encode(uint8_t *out, size_t out_cap, size_t *out_len);

int sodchan_wire_auth_fail_decode(const uint8_t *pdu, size_t len,
                                  uint8_t *reason, uint8_t *msg_len);

/* --- Mux PDUs --- */
int sodchan_wire_channel_open_encode(uint32_t sender_channel,
                                     uint32_t init_window,
                                     uint32_t max_packet,
                                     const char *name, size_t name_len,
                                     uint8_t *out, size_t out_cap,
                                     size_t *out_len);

int sodchan_wire_channel_open_decode(const uint8_t *pdu, size_t len,
                                     uint32_t *sender_channel,
                                     uint32_t *init_window,
                                     uint32_t *max_packet,
                                     char *name, size_t name_cap,
                                     size_t *name_len);

int sodchan_wire_channel_open_confirm_encode(uint32_t sender_channel,
                                             uint32_t recipient_channel,
                                             uint32_t init_window,
                                             uint32_t max_packet,
                                             uint8_t *out, size_t out_cap,
                                             size_t *out_len);

int sodchan_wire_channel_open_confirm_decode(const uint8_t *pdu, size_t len,
                                             uint32_t *sender_channel,
                                             uint32_t *recipient_channel,
                                             uint32_t *init_window,
                                             uint32_t *max_packet);

int sodchan_wire_channel_data_encode(uint32_t recipient_channel,
                                     const uint8_t *data, size_t data_len,
                                     uint8_t *out, size_t out_cap,
                                     size_t *out_len);

int sodchan_wire_channel_data_decode(const uint8_t *pdu, size_t len,
                                     uint32_t *recipient_channel,
                                     const uint8_t **data, size_t *data_len);

int sodchan_wire_channel_window_encode(uint32_t recipient_channel,
                                       uint32_t bytes_to_add,
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len);

int sodchan_wire_channel_eof_encode(uint32_t recipient_channel,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len);

int sodchan_wire_channel_close_encode(uint32_t recipient_channel,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len);

int sodchan_wire_ping_encode(uint32_t opaque, uint8_t *out, size_t out_cap,
                             size_t *out_len);

int sodchan_wire_pong_encode(uint32_t opaque, uint8_t *out, size_t out_cap,
                             size_t *out_len);

int sodchan_wire_disconnect_encode(uint32_t reason,
                                   const char *msg, size_t msg_len,
                                   uint8_t *out, size_t out_cap,
                                   size_t *out_len);

/** Read type byte; SODCHAN_ERR_PARAM if len==0. */
int sodchan_wire_pdu_type(const uint8_t *pdu, size_t len, uint8_t *type_out);

#ifdef __cplusplus
}
#endif

#endif /* SODCHAN_WIRE_H */
