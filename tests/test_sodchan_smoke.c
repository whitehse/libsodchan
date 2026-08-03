/**
 * @file test_sodchan_smoke.c
 * @brief PR-1 smoke: create/destroy, fail-closed pin, lab_mode gate.
 */

#include "sodchan.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Dummy identity material — not crypto-valid until PR-2; create only copies. */
static const uint8_t k_server_pk[SODCHAN_PUBKEY_BYTES] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};
static const uint8_t k_server_sk[SODCHAN_SECKEY_BYTES] = {
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
    0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
    0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
    0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0
};
static const uint8_t k_client_pk[SODCHAN_PUBKEY_BYTES] = {
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40
};
static const uint8_t k_client_sk[SODCHAN_SECKEY_BYTES] = {
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80
};

static void test_server_create_destroy(void)
{
    sodchan_config_t cfg;
    sodchan_ctx_t *s;
    uint8_t out[64];
    sodchan_event_t ev;

    memset(&cfg, 0, sizeof(cfg));
    cfg.server_id_pk = k_server_pk;
    cfg.server_id_sk = k_server_sk;

    s = sodchan_create(SODCHAN_ROLE_SERVER, &cfg);
    assert(s != NULL);
    assert(sodchan_current_state(s) == SODCHAN_STATE_IDLE);

    assert(sodchan_get_output(s, out, sizeof(out)) == 0);
    assert(sodchan_next_event(s, &ev) == 0);
    assert(sodchan_feed_input(s, out, 4) == 0);

    assert(sodchan_channel_open(s, SODCHAN_CHANNEL_EDGE_TELEMETRY, NULL) ==
           SODCHAN_ERR_STATE);
    assert(sodchan_auth_decide(s, 1) == SODCHAN_ERR_STATE);

    sodchan_reset(s);
    assert(sodchan_current_state(s) == SODCHAN_STATE_IDLE);

    assert(sodchan_disconnect(s, 0, "bye") == SODCHAN_OK);
    assert(sodchan_current_state(s) == SODCHAN_STATE_CLOSED);

    sodchan_destroy(s);
    printf("  PASS: server create/destroy/reset\n");
}

static void test_server_requires_keys(void)
{
    sodchan_config_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    assert(sodchan_create(SODCHAN_ROLE_SERVER, &cfg) == NULL);

    cfg.server_id_pk = k_server_pk;
    assert(sodchan_create(SODCHAN_ROLE_SERVER, &cfg) == NULL);

    cfg.server_id_sk = k_server_sk;
    {
        sodchan_ctx_t *s = sodchan_create(SODCHAN_ROLE_SERVER, &cfg);
        assert(s != NULL);
        sodchan_destroy(s);
    }
    printf("  PASS: server requires pk+sk\n");
}

static void test_client_fail_closed_pin(void)
{
    sodchan_config_t cfg;
    sodchan_ctx_t *c;

    memset(&cfg, 0, sizeof(cfg));
    cfg.client_id_pk = k_client_pk;
    cfg.client_id_sk = k_client_sk;
    /* accept_any_server_pk = 0, no pin → NULL */
    assert(sodchan_create(SODCHAN_ROLE_CLIENT, &cfg) == NULL);

    cfg.server_id_pk = k_server_pk;
    c = sodchan_create(SODCHAN_ROLE_CLIENT, &cfg);
    assert(c != NULL);
    assert(sodchan_current_state(c) == SODCHAN_STATE_IDLE);
    sodchan_destroy(c);
    printf("  PASS: client fail-closed pin\n");
}

static void test_client_accept_any(void)
{
    sodchan_config_t cfg;
    sodchan_ctx_t *c;

    memset(&cfg, 0, sizeof(cfg));
    cfg.accept_any_server_pk = 1;
    cfg.client_id_pk = k_client_pk;
    cfg.client_id_sk = k_client_sk;

    c = sodchan_create(SODCHAN_ROLE_CLIENT, &cfg);
    assert(c != NULL);
    sodchan_destroy(c);
    printf("  PASS: client accept_any_server_pk (lab)\n");
}

static void test_lab_mode_gate(void)
{
    sodchan_config_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.server_id_pk = k_server_pk;
    cfg.server_id_sk = k_server_sk;
    cfg.lab_mode = 1;

#ifndef SODCHAN_ALLOW_LAB_CLEARTEXT
    assert(sodchan_create(SODCHAN_ROLE_SERVER, &cfg) == NULL);
    printf("  PASS: lab_mode refused without SODCHAN_ALLOW_LAB_CLEARTEXT\n");
#else
    {
        sodchan_ctx_t *s = sodchan_create(SODCHAN_ROLE_SERVER, &cfg);
        assert(s != NULL);
        sodchan_destroy(s);
        printf("  PASS: lab_mode allowed (SODCHAN_ALLOW_LAB_CLEARTEXT)\n");
    }
#endif
}

static void test_null_cfg_and_destroy(void)
{
    /* NULL cfg server lacks keys → NULL */
    assert(sodchan_create(SODCHAN_ROLE_SERVER, NULL) == NULL);
    sodchan_destroy(NULL);
    sodchan_reset(NULL);
    printf("  PASS: null cfg/destroy safety\n");
}

static void test_keygen_stub(void)
{
    uint8_t pk[SODCHAN_PUBKEY_BYTES];
    uint8_t sk[SODCHAN_SECKEY_BYTES];
    char fp[SODCHAN_FP_SHA256_MAX];

    assert(sodchan_keygen_device(pk, sk) == SODCHAN_ERR_STATE);
    assert(sodchan_keygen_from_seed(pk, pk, sk) == SODCHAN_ERR_STATE);
    assert(sodchan_pubkey_fingerprint_sha256(pk, fp, sizeof(fp)) ==
           SODCHAN_ERR_STATE);
    printf("  PASS: keygen stubs return ERR_STATE (PR-2)\n");
}

int main(void)
{
    printf("libsodchan smoke test (PR-1 scaffold)...\n");
    test_server_create_destroy();
    test_server_requires_keys();
    test_client_fail_closed_pin();
    test_client_accept_any();
    test_lab_mode_gate();
    test_null_cfg_and_destroy();
    test_keygen_stub();
    printf("libsodchan smoke test PASSED.\n");
    return 0;
}
