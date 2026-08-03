/**
 * @file test_sodchan_wire.c
 * @brief PR-3: encode/decode + golden vectors (ADR 017).
 */

#include "sodchan.h"
#include "sodchan_wire.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- vector file loader --- */

typedef struct {
    char name[64];
    uint8_t *data;
    size_t len;
} vec_t;

#define MAX_VECS 32

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static int load_vectors(const char *path, vec_t *vecs, int max_vecs, int *out_n)
{
    FILE *f;
    char line[4096];
    vec_t *cur = NULL;
    int n = 0;

    f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        size_t L;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '#' || *p == '\n' || *p == '\0') {
            continue;
        }
        L = strlen(p);
        while (L > 0 && (p[L - 1] == '\n' || p[L - 1] == '\r' ||
                         p[L - 1] == ' ' || p[L - 1] == '\t')) {
            p[--L] = '\0';
        }
        if (L == 0) {
            continue;
        }

        /*
         * Name line: no whitespace (hex payload lines are space-separated pairs).
         * Names may start with A-F (e.g. AUTH_DEVICE) so do not use hex_nibble.
         */
        if (strchr(p, ' ') == NULL && strchr(p, '\t') == NULL) {
            if (n >= max_vecs) {
                fclose(f);
                return -1;
            }
            cur = &vecs[n++];
            memset(cur, 0, sizeof(*cur));
            strncpy(cur->name, p, sizeof(cur->name) - 1);
            continue;
        }

        if (!cur) {
            fclose(f);
            return -1;
        }

        /* Parse hex pairs */
        {
            size_t cap = cur->len + 512;
            uint8_t *nd = (uint8_t *)realloc(cur->data, cap > cur->len + 256
                                                            ? cur->len + 1024
                                                            : cur->len + 256);
            size_t i;
            if (!nd) {
                fclose(f);
                return -1;
            }
            cur->data = nd;
            for (i = 0; p[i];) {
                int hi, lo;
                while (p[i] == ' ' || p[i] == '\t') {
                    i++;
                }
                if (!p[i]) {
                    break;
                }
                hi = hex_nibble((unsigned char)p[i++]);
                if (hi < 0 || !p[i]) {
                    fclose(f);
                    return -1;
                }
                lo = hex_nibble((unsigned char)p[i++]);
                if (lo < 0) {
                    fclose(f);
                    return -1;
                }
                if (cur->len >= cap) {
                    cap *= 2;
                    nd = (uint8_t *)realloc(cur->data, cap);
                    if (!nd) {
                        fclose(f);
                        return -1;
                    }
                    cur->data = nd;
                }
                cur->data[cur->len++] = (uint8_t)((hi << 4) | lo);
            }
        }
    }
    fclose(f);
    *out_n = n;
    return 0;
}

static const vec_t *find_vec(const vec_t *vecs, int n, const char *name)
{
    int i;
    for (i = 0; i < n; i++) {
        if (strcmp(vecs[i].name, name) == 0) {
            return &vecs[i];
        }
    }
    return NULL;
}

static void free_vectors(vec_t *vecs, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        free(vecs[i].data);
    }
}

static void fill_range(uint8_t *p, size_t n, uint8_t start)
{
    size_t i;
    for (i = 0; i < n; i++) {
        p[i] = (uint8_t)(start + i);
    }
}

static void assert_mem_eq(const uint8_t *a, const uint8_t *b, size_t n,
                          const char *what)
{
    if (memcmp(a, b, n) != 0) {
        size_t i;
        fprintf(stderr, "FAIL: %s mismatch\n", what);
        fprintf(stderr, " got:");
        for (i = 0; i < n && i < 64; i++) {
            fprintf(stderr, " %02x", a[i]);
        }
        fprintf(stderr, "\n exp:");
        for (i = 0; i < n && i < 64; i++) {
            fprintf(stderr, " %02x", b[i]);
        }
        fprintf(stderr, "\n");
        assert(0);
    }
}

static void test_be_ints(void)
{
    uint8_t b[4];
    sodchan_wire_put_u16(b, 0x5343);
    assert(b[0] == 0x53 && b[1] == 0x43);
    assert(sodchan_wire_get_u16(b) == 0x5343);
    sodchan_wire_put_u32(b, 140);
    assert(b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0x8c);
    assert(sodchan_wire_get_u32(b) == 140);
    printf("  PASS: big-endian u16/u32\n");
}

static void test_hello_roundtrip_and_vector(const vec_t *v_body, const vec_t *v_frame)
{
    sodchan_hello_t h, h2;
    uint8_t body[SODCHAN_HELLO_BODY_LEN];
    uint8_t frame[160];
    size_t blen = 0, flen = 0, consumed = 0;
    const uint8_t *parsed_body = NULL;
    size_t parsed_len = 0;

    memset(&h, 0, sizeof(h));
    h.proto_version = SODCHAN_PROTO_VERSION;
    h.suite_id = SODCHAN_SUITE_V1;
    h.role = SODCHAN_ROLE_CLIENT;
    h.flags = 0;
    fill_range(h.eph_pk, 32, 0x00);
    fill_range(h.id_pk, 32, 0x60);
    /* id_sig zeros */

    assert(sodchan_wire_hello_encode(&h, body, sizeof(body), &blen) == SODCHAN_OK);
    assert(blen == 140);
    assert_mem_eq(body, v_body->data, v_body->len, "HELLO_CLIENT_BODY");

    assert(sodchan_wire_hello_decode(body, blen, &h2) == SODCHAN_OK);
    assert(h2.role == SODCHAN_ROLE_CLIENT);
    assert(memcmp(h2.eph_pk, h.eph_pk, 32) == 0);
    assert(memcmp(h2.id_pk, h.id_pk, 32) == 0);

    assert(sodchan_wire_frame_encode(body, blen, frame, sizeof(frame), &flen) ==
           SODCHAN_OK);
    assert(flen == 144);
    assert_mem_eq(frame, v_frame->data, v_frame->len, "HELLO_CLIENT_FRAME");

    assert(sodchan_wire_frame_parse(frame, flen, &consumed, &parsed_body,
                                    &parsed_len) == SODCHAN_OK);
    assert(consumed == 144 && parsed_len == 140);

    /* Truncated / bad frames */
    assert(sodchan_wire_frame_parse(frame, 3, &consumed, &parsed_body,
                                    &parsed_len) == SODCHAN_ERR_FULL);
    {
        uint8_t bad[8] = {0, 0, 0, 0};
        assert(sodchan_wire_frame_parse(bad, 4, &consumed, &parsed_body,
                                        &parsed_len) == SODCHAN_ERR_PROTOCOL);
    }

    /* Bad magic */
    body[0] = 0x00;
    assert(sodchan_wire_hello_decode(body, blen, &h2) == SODCHAN_ERR_PROTOCOL);

    printf("  PASS: HELLO encode/decode + frame vectors\n");
}

static void test_server_hello_vector(const vec_t *v_body)
{
    sodchan_hello_t h;
    uint8_t body[SODCHAN_HELLO_BODY_LEN];
    size_t blen = 0;
    int i;

    memset(&h, 0, sizeof(h));
    h.proto_version = SODCHAN_PROTO_VERSION;
    h.suite_id = SODCHAN_SUITE_V1;
    h.role = SODCHAN_ROLE_SERVER;
    fill_range(h.eph_pk, 32, 0x20);
    fill_range(h.id_pk, 32, 0x40);
    for (i = 0; i < 64; i++) {
        h.id_sig[i] = (uint8_t)((i * 3) & 0xff);
    }

    assert(sodchan_wire_hello_encode(&h, body, sizeof(body), &blen) == SODCHAN_OK);
    assert_mem_eq(body, v_body->data, v_body->len, "HELLO_SERVER_BODY");
    printf("  PASS: HELLO server body vector\n");
}

static void test_transcripts(const vec_t *v_th, const vec_t *v_ta)
{
    uint8_t client_eph[32], server_eph[32], server_id[32], client_id[32];
    uint8_t t_hello[SODCHAN_T_HELLO_LEN];
    uint8_t t_auth[512];
    size_t t_auth_len = 0;

    fill_range(client_eph, 32, 0x00);
    fill_range(server_eph, 32, 0x20);
    fill_range(server_id, 32, 0x40);
    fill_range(client_id, 32, 0x60);

    assert(sodchan_wire_build_t_hello(1, 1, client_eph, server_eph, server_id,
                                      t_hello) == SODCHAN_OK);
    assert(SODCHAN_T_HELLO_LEN == 123);
    assert(v_th->len == 123);
    assert_mem_eq(t_hello, v_th->data, v_th->len, "T_HELLO");

    assert(sodchan_wire_build_t_auth(t_hello, client_id, "alice", 5, "dev-1", 5,
                                     t_auth, sizeof(t_auth),
                                     &t_auth_len) == SODCHAN_OK);
    assert(t_auth_len == v_ta->len);
    assert_mem_eq(t_auth, v_ta->data, v_ta->len, "T_AUTH");

    /* DOM length sanity */
    assert(strlen(SODCHAN_DOM_SERVER_HELLO) == SODCHAN_DOM_SERVER_HELLO_LEN);
    assert(strlen(SODCHAN_DOM_CLIENT_AUTH) == SODCHAN_DOM_CLIENT_AUTH_LEN);

    printf("  PASS: T_hello / T_auth transcripts\n");
}

static void test_auth_pdus(const vec_t *v_dev, const vec_t *v_ok,
                           const vec_t *v_fail)
{
    uint8_t client_id[32], sig[64];
    uint8_t buf[256];
    size_t len = 0;
    uint8_t pk2[32], sig2[64];
    char user[64], device[64];
    size_t ulen = 0, dlen = 0;
    const uint8_t *claims = NULL;
    size_t claims_len = 0;
    uint8_t reason = 0xff, msg_len = 0xff;
    int i;

    fill_range(client_id, 32, 0x60);
    for (i = 0; i < 64; i++) {
        sig[i] = (uint8_t)(0xa0 + (i % 16));
    }

    assert(sodchan_wire_auth_device_encode(client_id, sig, "alice", 5, "dev-1",
                                           5, buf, sizeof(buf), &len) ==
           SODCHAN_OK);
    assert_mem_eq(buf, v_dev->data, v_dev->len, "AUTH_DEVICE");

    assert(sodchan_wire_auth_device_decode(buf, len, pk2, sig2, user,
                                           sizeof(user), &ulen, device,
                                           sizeof(device), &dlen) == SODCHAN_OK);
    assert(ulen == 5 && strcmp(user, "alice") == 0);
    assert(dlen == 5 && strcmp(device, "dev-1") == 0);
    assert(memcmp(pk2, client_id, 32) == 0);

    assert(sodchan_wire_auth_ok_encode((const uint8_t *)"{\"sub\":\"alice\"}", 15,
                                       buf, sizeof(buf), &len) == SODCHAN_OK);
    assert_mem_eq(buf, v_ok->data, v_ok->len, "AUTH_OK");
    assert(sodchan_wire_auth_ok_decode(buf, len, &claims, &claims_len) ==
           SODCHAN_OK);
    assert(claims_len == 15);

    assert(sodchan_wire_auth_fail_encode(buf, sizeof(buf), &len) == SODCHAN_OK);
    assert(len == 3);
    assert_mem_eq(buf, v_fail->data, v_fail->len, "AUTH_FAIL");
    assert(sodchan_wire_auth_fail_decode(buf, len, &reason, &msg_len) ==
           SODCHAN_OK);
    assert(reason == SODCHAN_AUTH_FAIL_UNSPEC && msg_len == 0);

    printf("  PASS: AUTH_DEVICE / AUTH_OK / AUTH_FAIL\n");
}

static void test_mux_pdus(const vec_t *v_open, const vec_t *v_conf,
                          const vec_t *v_data)
{
    uint8_t buf[128];
    size_t len = 0;
    uint32_t sc = 0, rc = 0, iw = 0, mp = 0;
    char name[64];
    size_t nlen = 0;
    const uint8_t *data = NULL;
    size_t dlen = 0;

    assert(sodchan_wire_channel_open_encode(0, 262144, 65536, "edge-telemetry",
                                            14, buf, sizeof(buf),
                                            &len) == SODCHAN_OK);
    assert_mem_eq(buf, v_open->data, v_open->len, "CHANNEL_OPEN");
    assert(sodchan_wire_channel_open_decode(buf, len, &sc, &iw, &mp, name,
                                            sizeof(name), &nlen) == SODCHAN_OK);
    assert(sc == 0 && iw == 262144 && mp == 65536);
    assert(strcmp(name, "edge-telemetry") == 0);

    assert(sodchan_wire_channel_open_confirm_encode(1, 0, 262144, 65536, buf,
                                                    sizeof(buf),
                                                    &len) == SODCHAN_OK);
    assert_mem_eq(buf, v_conf->data, v_conf->len, "CHANNEL_OPEN_CONFIRM");
    assert(sodchan_wire_channel_open_confirm_decode(buf, len, &sc, &rc, &iw,
                                                    &mp) == SODCHAN_OK);
    assert(sc == 1 && rc == 0);

    assert(sodchan_wire_channel_data_encode(0, (const uint8_t *)"hello", 5, buf,
                                            sizeof(buf), &len) == SODCHAN_OK);
    assert_mem_eq(buf, v_data->data, v_data->len, "CHANNEL_DATA");
    assert(sodchan_wire_channel_data_decode(buf, len, &rc, &data, &dlen) ==
           SODCHAN_OK);
    assert(rc == 0 && dlen == 5 && memcmp(data, "hello", 5) == 0);

    assert(sodchan_wire_channel_window_encode(0, 1000, buf, sizeof(buf), &len) ==
           SODCHAN_OK);
    assert(len == 9);
    assert(sodchan_wire_channel_eof_encode(0, buf, sizeof(buf), &len) ==
           SODCHAN_OK);
    assert(len == 5);
    assert(sodchan_wire_channel_close_encode(0, buf, sizeof(buf), &len) ==
           SODCHAN_OK);
    assert(sodchan_wire_ping_encode(0xdeadbeef, buf, sizeof(buf), &len) ==
           SODCHAN_OK);
    assert(sodchan_wire_pong_encode(0xdeadbeef, buf, sizeof(buf), &len) ==
           SODCHAN_OK);
    assert(sodchan_wire_disconnect_encode(SODCHAN_REASON_BY_APPLICATION, "bye",
                                          3, buf, sizeof(buf),
                                          &len) == SODCHAN_OK);
    assert(buf[0] == SODCHAN_PDU_DISCONNECT);

    printf("  PASS: mux PDU encode/decode\n");
}

static void test_reject_wrong_version(void)
{
    sodchan_hello_t h;
    uint8_t body[SODCHAN_HELLO_BODY_LEN];
    size_t blen = 0;

    memset(&h, 0, sizeof(h));
    h.proto_version = 99;
    h.suite_id = SODCHAN_SUITE_V1;
    h.role = SODCHAN_ROLE_CLIENT;
    assert(sodchan_wire_hello_encode(&h, body, sizeof(body), &blen) == SODCHAN_OK);
    /* encode writes fields; decode rejects bad version */
    assert(sodchan_wire_hello_decode(body, blen, &h) == SODCHAN_ERR_PROTOCOL);

    h.proto_version = SODCHAN_PROTO_VERSION;
    h.suite_id = 99;
    assert(sodchan_wire_hello_encode(&h, body, sizeof(body), &blen) == SODCHAN_OK);
    assert(sodchan_wire_hello_decode(body, blen, &h) == SODCHAN_ERR_PROTOCOL);
    printf("  PASS: reject wrong version/suite\n");
}

int main(int argc, char **argv)
{
    const char *path = "tests/vectors/handshake_v1.hex";
    vec_t vecs[MAX_VECS];
    int n = 0;
    const vec_t *v;

    if (argc > 1) {
        path = argv[1];
    }

    printf("libsodchan wire test (PR-3 / ADR 017)...\n");
    printf("  vectors: %s\n", path);

    if (load_vectors(path, vecs, MAX_VECS, &n) != 0) {
        /* try from build dir */
        path = "../tests/vectors/handshake_v1.hex";
        if (load_vectors(path, vecs, MAX_VECS, &n) != 0) {
            fprintf(stderr, "cannot load vectors\n");
            return 1;
        }
    }

    test_be_ints();

    v = find_vec(vecs, n, "HELLO_CLIENT_BODY");
    assert(v);
    test_hello_roundtrip_and_vector(v, find_vec(vecs, n, "HELLO_CLIENT_FRAME"));
    test_server_hello_vector(find_vec(vecs, n, "HELLO_SERVER_BODY"));
    test_transcripts(find_vec(vecs, n, "T_HELLO"), find_vec(vecs, n, "T_AUTH"));
    test_auth_pdus(find_vec(vecs, n, "AUTH_DEVICE"), find_vec(vecs, n, "AUTH_OK"),
                   find_vec(vecs, n, "AUTH_FAIL"));
    test_mux_pdus(find_vec(vecs, n, "CHANNEL_OPEN"),
                  find_vec(vecs, n, "CHANNEL_OPEN_CONFIRM"),
                  find_vec(vecs, n, "CHANNEL_DATA"));
    test_reject_wrong_version();

    free_vectors(vecs, n);
    printf("libsodchan wire test PASSED.\n");
    return 0;
}
