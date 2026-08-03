/**
 * @file sodchan_wire.c
 * @brief Normative HELLO / AUTH / mux encode-decode (ADR 017).
 */

#include "sodchan_wire.h"

#include <string.h>

void sodchan_wire_put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

void sodchan_wire_put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

uint16_t sodchan_wire_get_u16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

uint32_t sodchan_wire_get_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int sodchan_wire_frame_encode(const uint8_t *body, size_t body_len,
                              uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!body || !out || !out_len || body_len == 0) {
        return SODCHAN_ERR_PARAM;
    }
    if (body_len > SODCHAN_MAX_CLEAR_FRAME) {
        return SODCHAN_ERR_PROTOCOL;
    }
    if (out_cap < 4 + body_len) {
        return SODCHAN_ERR_FULL;
    }
    sodchan_wire_put_u32(out, (uint32_t)body_len);
    memcpy(out + 4, body, body_len);
    *out_len = 4 + body_len;
    return SODCHAN_OK;
}

int sodchan_wire_frame_parse(const uint8_t *data, size_t len,
                             size_t *consumed,
                             const uint8_t **body, size_t *body_len)
{
    uint32_t L;

    if (!data || !consumed || !body || !body_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (len < 4) {
        return SODCHAN_ERR_FULL; /* need more */
    }
    L = sodchan_wire_get_u32(data);
    if (L == 0 || L > SODCHAN_MAX_CLEAR_FRAME) {
        return SODCHAN_ERR_PROTOCOL;
    }
    if (len < 4 + (size_t)L) {
        return SODCHAN_ERR_FULL;
    }
    *body = data + 4;
    *body_len = L;
    *consumed = 4 + (size_t)L;
    return SODCHAN_OK;
}

int sodchan_wire_hello_encode(const sodchan_hello_t *h,
                              uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!h || !out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (out_cap < SODCHAN_HELLO_BODY_LEN) {
        return SODCHAN_ERR_FULL;
    }
    sodchan_wire_put_u16(out + 0, SODCHAN_MAGIC);
    sodchan_wire_put_u16(out + 2, h->proto_version);
    sodchan_wire_put_u16(out + 4, h->suite_id);
    sodchan_wire_put_u16(out + 6, h->role);
    sodchan_wire_put_u32(out + 8, h->flags);
    memcpy(out + 12, h->eph_pk, 32);
    memcpy(out + 44, h->id_pk, 32);
    memcpy(out + 76, h->id_sig, 64);
    *out_len = SODCHAN_HELLO_BODY_LEN;
    return SODCHAN_OK;
}

int sodchan_wire_hello_decode(const uint8_t *body, size_t len,
                              sodchan_hello_t *h)
{
    uint16_t magic;

    if (!body || !h) {
        return SODCHAN_ERR_PARAM;
    }
    if (len != SODCHAN_HELLO_BODY_LEN) {
        return SODCHAN_ERR_PROTOCOL;
    }
    magic = sodchan_wire_get_u16(body + 0);
    if (magic != SODCHAN_MAGIC) {
        return SODCHAN_ERR_PROTOCOL;
    }
    h->proto_version = sodchan_wire_get_u16(body + 2);
    h->suite_id = sodchan_wire_get_u16(body + 4);
    h->role = sodchan_wire_get_u16(body + 6);
    h->flags = sodchan_wire_get_u32(body + 8);
    memcpy(h->eph_pk, body + 12, 32);
    memcpy(h->id_pk, body + 44, 32);
    memcpy(h->id_sig, body + 76, 64);

    if (h->proto_version != SODCHAN_PROTO_VERSION ||
        h->suite_id != SODCHAN_SUITE_V1) {
        return SODCHAN_ERR_PROTOCOL;
    }
    if (h->role != SODCHAN_ROLE_SERVER && h->role != SODCHAN_ROLE_CLIENT) {
        return SODCHAN_ERR_PROTOCOL;
    }
    return SODCHAN_OK;
}

int sodchan_wire_build_t_hello(uint16_t proto_version, uint16_t suite_id,
                               const uint8_t client_eph_pk[32],
                               const uint8_t server_eph_pk[32],
                               const uint8_t server_id_pk[32],
                               uint8_t out[SODCHAN_T_HELLO_LEN])
{
    static const char dom[] = SODCHAN_DOM_SERVER_HELLO;
    size_t off = 0;

    if (!client_eph_pk || !server_eph_pk || !server_id_pk || !out) {
        return SODCHAN_ERR_PARAM;
    }
    /* Compile-time length check: string includes trailing NUL in sizeof. */
    if (sizeof(dom) - 1u != SODCHAN_DOM_SERVER_HELLO_LEN) {
        return SODCHAN_ERR_PROTOCOL;
    }
    memcpy(out + off, dom, SODCHAN_DOM_SERVER_HELLO_LEN);
    off += SODCHAN_DOM_SERVER_HELLO_LEN;
    sodchan_wire_put_u16(out + off, proto_version);
    off += 2;
    sodchan_wire_put_u16(out + off, suite_id);
    off += 2;
    memcpy(out + off, client_eph_pk, 32);
    off += 32;
    memcpy(out + off, server_eph_pk, 32);
    off += 32;
    memcpy(out + off, server_id_pk, 32);
    off += 32;
    if (off != SODCHAN_T_HELLO_LEN) {
        return SODCHAN_ERR_PROTOCOL;
    }
    return SODCHAN_OK;
}

int sodchan_wire_build_t_auth(const uint8_t t_hello[SODCHAN_T_HELLO_LEN],
                              const uint8_t client_id_pk[32],
                              const char *username, size_t username_len,
                              const char *device_id, size_t device_id_len,
                              uint8_t *out, size_t out_cap, size_t *out_len)
{
    static const char dom[] = SODCHAN_DOM_CLIENT_AUTH;
    size_t need;
    size_t off = 0;

    if (!t_hello || !client_id_pk || !out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (username_len > SODCHAN_USER_MAX || device_id_len > SODCHAN_DEVICE_ID_MAX) {
        return SODCHAN_ERR_PARAM;
    }
    if (username_len > 0 && !username) {
        return SODCHAN_ERR_PARAM;
    }
    if (device_id_len > 0 && !device_id) {
        return SODCHAN_ERR_PARAM;
    }
    if (sizeof(dom) - 1u != SODCHAN_DOM_CLIENT_AUTH_LEN) {
        return SODCHAN_ERR_PROTOCOL;
    }

    need = SODCHAN_DOM_CLIENT_AUTH_LEN + SODCHAN_T_HELLO_LEN + 32 + 1 +
           username_len + 1 + device_id_len;
    if (out_cap < need) {
        return SODCHAN_ERR_FULL;
    }

    memcpy(out + off, dom, SODCHAN_DOM_CLIENT_AUTH_LEN);
    off += SODCHAN_DOM_CLIENT_AUTH_LEN;
    memcpy(out + off, t_hello, SODCHAN_T_HELLO_LEN);
    off += SODCHAN_T_HELLO_LEN;
    memcpy(out + off, client_id_pk, 32);
    off += 32;
    out[off++] = (uint8_t)username_len;
    if (username_len) {
        memcpy(out + off, username, username_len);
        off += username_len;
    }
    out[off++] = (uint8_t)device_id_len;
    if (device_id_len) {
        memcpy(out + off, device_id, device_id_len);
        off += device_id_len;
    }
    *out_len = off;
    return SODCHAN_OK;
}

int sodchan_wire_auth_device_encode(const uint8_t client_id_pk[32],
                                    const uint8_t client_sig[64],
                                    const char *username, size_t username_len,
                                    const char *device_id, size_t device_id_len,
                                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t need;
    size_t off = 0;

    if (!client_id_pk || !client_sig || !out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (username_len > SODCHAN_USER_MAX || device_id_len > SODCHAN_DEVICE_ID_MAX) {
        return SODCHAN_ERR_PARAM;
    }
    if ((username_len > 0 && !username) || (device_id_len > 0 && !device_id)) {
        return SODCHAN_ERR_PARAM;
    }

    need = 1 + 32 + 64 + 1 + username_len + 1 + device_id_len;
    if (out_cap < need) {
        return SODCHAN_ERR_FULL;
    }

    out[off++] = (uint8_t)SODCHAN_PDU_AUTH_DEVICE;
    memcpy(out + off, client_id_pk, 32);
    off += 32;
    memcpy(out + off, client_sig, 64);
    off += 64;
    out[off++] = (uint8_t)username_len;
    if (username_len) {
        memcpy(out + off, username, username_len);
        off += username_len;
    }
    out[off++] = (uint8_t)device_id_len;
    if (device_id_len) {
        memcpy(out + off, device_id, device_id_len);
        off += device_id_len;
    }
    *out_len = off;
    return SODCHAN_OK;
}

int sodchan_wire_auth_device_decode(const uint8_t *pdu, size_t len,
                                    uint8_t client_id_pk[32],
                                    uint8_t client_sig[64],
                                    char *username, size_t username_cap,
                                    size_t *username_len,
                                    char *device_id, size_t device_id_cap,
                                    size_t *device_id_len)
{
    size_t off = 0;
    uint8_t ulen, dlen;

    if (!pdu || !client_id_pk || !client_sig || !username_len || !device_id_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (len < 1 + 32 + 64 + 1 + 1) {
        return SODCHAN_ERR_PROTOCOL;
    }
    if (pdu[off++] != SODCHAN_PDU_AUTH_DEVICE) {
        return SODCHAN_ERR_PROTOCOL;
    }
    memcpy(client_id_pk, pdu + off, 32);
    off += 32;
    memcpy(client_sig, pdu + off, 64);
    off += 64;
    ulen = pdu[off++];
    if (ulen > SODCHAN_USER_MAX || off + ulen + 1 > len) {
        return SODCHAN_ERR_PROTOCOL;
    }
    if (username && username_cap > 0) {
        size_t copy = ulen;
        if (copy >= username_cap) {
            copy = username_cap - 1;
        }
        if (ulen) {
            memcpy(username, pdu + off, copy);
        }
        username[copy] = '\0';
    }
    *username_len = ulen;
    off += ulen;
    dlen = pdu[off++];
    if (dlen > SODCHAN_DEVICE_ID_MAX || off + dlen > len) {
        return SODCHAN_ERR_PROTOCOL;
    }
    if (off + dlen != len) {
        return SODCHAN_ERR_PROTOCOL; /* no trailing junk */
    }
    if (device_id && device_id_cap > 0) {
        size_t copy = dlen;
        if (copy >= device_id_cap) {
            copy = device_id_cap - 1;
        }
        if (dlen) {
            memcpy(device_id, pdu + off, copy);
        }
        device_id[copy] = '\0';
    }
    *device_id_len = dlen;
    return SODCHAN_OK;
}

int sodchan_wire_auth_ok_encode(const uint8_t *claims, size_t claims_len,
                                uint8_t *out, size_t out_cap, size_t *out_len)
{
    size_t need;

    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (claims_len > SODCHAN_CLAIMS_MAX) {
        return SODCHAN_ERR_PARAM;
    }
    if (claims_len > 0 && !claims) {
        return SODCHAN_ERR_PARAM;
    }
    need = 1 + 2 + claims_len;
    if (out_cap < need) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_AUTH_OK;
    sodchan_wire_put_u16(out + 1, (uint16_t)claims_len);
    if (claims_len) {
        memcpy(out + 3, claims, claims_len);
    }
    *out_len = need;
    return SODCHAN_OK;
}

int sodchan_wire_auth_ok_decode(const uint8_t *pdu, size_t len,
                                const uint8_t **claims, size_t *claims_len)
{
    uint16_t C;

    if (!pdu || !claims || !claims_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (len < 3 || pdu[0] != SODCHAN_PDU_AUTH_OK) {
        return SODCHAN_ERR_PROTOCOL;
    }
    C = sodchan_wire_get_u16(pdu + 1);
    if (C > SODCHAN_CLAIMS_MAX || len != 3 + (size_t)C) {
        return SODCHAN_ERR_PROTOCOL;
    }
    *claims = (C > 0) ? (pdu + 3) : NULL;
    *claims_len = C;
    return SODCHAN_OK;
}

int sodchan_wire_auth_fail_encode(uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (out_cap < 3) {
        return SODCHAN_ERR_FULL;
    }
    /* Wire: type, reason=UNSPEC, msg_len=0 */
    out[0] = (uint8_t)SODCHAN_PDU_AUTH_FAIL;
    out[1] = (uint8_t)SODCHAN_AUTH_FAIL_UNSPEC;
    out[2] = 0;
    *out_len = 3;
    return SODCHAN_OK;
}

int sodchan_wire_auth_fail_decode(const uint8_t *pdu, size_t len,
                                  uint8_t *reason, uint8_t *msg_len)
{
    if (!pdu || !reason || !msg_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (len < 3 || pdu[0] != SODCHAN_PDU_AUTH_FAIL) {
        return SODCHAN_ERR_PROTOCOL;
    }
    *reason = pdu[1];
    *msg_len = pdu[2];
    if (len != 3 + (size_t)pdu[2]) {
        return SODCHAN_ERR_PROTOCOL;
    }
    return SODCHAN_OK;
}

int sodchan_wire_channel_open_encode(uint32_t sender_channel,
                                     uint32_t init_window,
                                     uint32_t max_packet,
                                     const char *name, size_t name_len,
                                     uint8_t *out, size_t out_cap,
                                     size_t *out_len)
{
    size_t need;

    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (name_len > SODCHAN_CHANNEL_NAME_MAX || (name_len > 0 && !name)) {
        return SODCHAN_ERR_PARAM;
    }
    need = 1 + 4 + 4 + 4 + 1 + name_len;
    if (out_cap < need) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_CHANNEL_OPEN;
    sodchan_wire_put_u32(out + 1, sender_channel);
    sodchan_wire_put_u32(out + 5, init_window);
    sodchan_wire_put_u32(out + 9, max_packet);
    out[13] = (uint8_t)name_len;
    if (name_len) {
        memcpy(out + 14, name, name_len);
    }
    *out_len = need;
    return SODCHAN_OK;
}

int sodchan_wire_channel_open_decode(const uint8_t *pdu, size_t len,
                                     uint32_t *sender_channel,
                                     uint32_t *init_window,
                                     uint32_t *max_packet,
                                     char *name, size_t name_cap,
                                     size_t *name_len)
{
    uint8_t nlen;

    if (!pdu || !sender_channel || !init_window || !max_packet || !name_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (len < 14 || pdu[0] != SODCHAN_PDU_CHANNEL_OPEN) {
        return SODCHAN_ERR_PROTOCOL;
    }
    *sender_channel = sodchan_wire_get_u32(pdu + 1);
    *init_window = sodchan_wire_get_u32(pdu + 5);
    *max_packet = sodchan_wire_get_u32(pdu + 9);
    nlen = pdu[13];
    if (nlen > SODCHAN_CHANNEL_NAME_MAX || len != 14 + (size_t)nlen) {
        return SODCHAN_ERR_PROTOCOL;
    }
    *name_len = nlen;
    if (name && name_cap > 0) {
        size_t copy = nlen;
        if (copy >= name_cap) {
            copy = name_cap - 1;
        }
        if (nlen) {
            memcpy(name, pdu + 14, copy);
        }
        name[copy] = '\0';
    }
    return SODCHAN_OK;
}

int sodchan_wire_channel_open_confirm_encode(uint32_t sender_channel,
                                             uint32_t recipient_channel,
                                             uint32_t init_window,
                                             uint32_t max_packet,
                                             uint8_t *out, size_t out_cap,
                                             size_t *out_len)
{
    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (out_cap < 17) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_CHANNEL_OPEN_CONFIRM;
    sodchan_wire_put_u32(out + 1, sender_channel);
    sodchan_wire_put_u32(out + 5, recipient_channel);
    sodchan_wire_put_u32(out + 9, init_window);
    sodchan_wire_put_u32(out + 13, max_packet);
    *out_len = 17;
    return SODCHAN_OK;
}

int sodchan_wire_channel_open_confirm_decode(const uint8_t *pdu, size_t len,
                                             uint32_t *sender_channel,
                                             uint32_t *recipient_channel,
                                             uint32_t *init_window,
                                             uint32_t *max_packet)
{
    if (!pdu || !sender_channel || !recipient_channel || !init_window ||
        !max_packet) {
        return SODCHAN_ERR_PARAM;
    }
    if (len != 17 || pdu[0] != SODCHAN_PDU_CHANNEL_OPEN_CONFIRM) {
        return SODCHAN_ERR_PROTOCOL;
    }
    *sender_channel = sodchan_wire_get_u32(pdu + 1);
    *recipient_channel = sodchan_wire_get_u32(pdu + 5);
    *init_window = sodchan_wire_get_u32(pdu + 9);
    *max_packet = sodchan_wire_get_u32(pdu + 13);
    return SODCHAN_OK;
}

int sodchan_wire_channel_data_encode(uint32_t recipient_channel,
                                     const uint8_t *data, size_t data_len,
                                     uint8_t *out, size_t out_cap,
                                     size_t *out_len)
{
    size_t need;

    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (data_len > 0 && !data) {
        return SODCHAN_ERR_PARAM;
    }
    if (data_len > 0xFFFFFFFFu - 9u) {
        return SODCHAN_ERR_PARAM;
    }
    need = 1 + 4 + 4 + data_len;
    if (out_cap < need) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_CHANNEL_DATA;
    sodchan_wire_put_u32(out + 1, recipient_channel);
    sodchan_wire_put_u32(out + 5, (uint32_t)data_len);
    if (data_len) {
        memcpy(out + 9, data, data_len);
    }
    *out_len = need;
    return SODCHAN_OK;
}

int sodchan_wire_channel_data_decode(const uint8_t *pdu, size_t len,
                                     uint32_t *recipient_channel,
                                     const uint8_t **data, size_t *data_len)
{
    uint32_t dlen;

    if (!pdu || !recipient_channel || !data || !data_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (len < 9 || pdu[0] != SODCHAN_PDU_CHANNEL_DATA) {
        return SODCHAN_ERR_PROTOCOL;
    }
    *recipient_channel = sodchan_wire_get_u32(pdu + 1);
    dlen = sodchan_wire_get_u32(pdu + 5);
    if (len != 9 + (size_t)dlen) {
        return SODCHAN_ERR_PROTOCOL;
    }
    *data_len = dlen;
    *data = dlen ? (pdu + 9) : NULL;
    return SODCHAN_OK;
}

int sodchan_wire_channel_window_encode(uint32_t recipient_channel,
                                       uint32_t bytes_to_add,
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len)
{
    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (out_cap < 9) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_CHANNEL_WINDOW;
    sodchan_wire_put_u32(out + 1, recipient_channel);
    sodchan_wire_put_u32(out + 5, bytes_to_add);
    *out_len = 9;
    return SODCHAN_OK;
}

int sodchan_wire_channel_eof_encode(uint32_t recipient_channel,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len)
{
    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (out_cap < 5) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_CHANNEL_EOF;
    sodchan_wire_put_u32(out + 1, recipient_channel);
    *out_len = 5;
    return SODCHAN_OK;
}

int sodchan_wire_channel_close_encode(uint32_t recipient_channel,
                                      uint8_t *out, size_t out_cap,
                                      size_t *out_len)
{
    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (out_cap < 5) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_CHANNEL_CLOSE;
    sodchan_wire_put_u32(out + 1, recipient_channel);
    *out_len = 5;
    return SODCHAN_OK;
}

int sodchan_wire_ping_encode(uint32_t opaque, uint8_t *out, size_t out_cap,
                             size_t *out_len)
{
    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (out_cap < 5) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_PING;
    sodchan_wire_put_u32(out + 1, opaque);
    *out_len = 5;
    return SODCHAN_OK;
}

int sodchan_wire_pong_encode(uint32_t opaque, uint8_t *out, size_t out_cap,
                             size_t *out_len)
{
    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (out_cap < 5) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_PONG;
    sodchan_wire_put_u32(out + 1, opaque);
    *out_len = 5;
    return SODCHAN_OK;
}

int sodchan_wire_disconnect_encode(uint32_t reason,
                                   const char *msg, size_t msg_len,
                                   uint8_t *out, size_t out_cap,
                                   size_t *out_len)
{
    size_t need;

    if (!out || !out_len) {
        return SODCHAN_ERR_PARAM;
    }
    if (msg_len > 255 || (msg_len > 0 && !msg)) {
        return SODCHAN_ERR_PARAM;
    }
    need = 1 + 4 + 1 + msg_len;
    if (out_cap < need) {
        return SODCHAN_ERR_FULL;
    }
    out[0] = (uint8_t)SODCHAN_PDU_DISCONNECT;
    sodchan_wire_put_u32(out + 1, reason);
    out[5] = (uint8_t)msg_len;
    if (msg_len) {
        memcpy(out + 6, msg, msg_len);
    }
    *out_len = need;
    return SODCHAN_OK;
}

int sodchan_wire_pdu_type(const uint8_t *pdu, size_t len, uint8_t *type_out)
{
    if (!pdu || !type_out || len == 0) {
        return SODCHAN_ERR_PARAM;
    }
    *type_out = pdu[0];
    return SODCHAN_OK;
}
