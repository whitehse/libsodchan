/**
 * @file test_sodchan_mitm_pin.c
 * @brief PR-4 K16: MITM presents correct server_id_pk but wrong sk / eph → reject.
 */

#include "sodchan.h"
#include "sodchan_wire.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

/*
 * Build a forged server HELLO: correct id_pk (pin), attacker eph_pk,
 * signature made with attacker_sk (not the real server sk).
 */
static size_t build_forged_server_hello_frame(const uint8_t *client_eph,
                                              const uint8_t *server_id_pk,
                                              const uint8_t *attacker_sk,
                                              uint8_t *out, size_t out_cap)
{
    uint8_t attacker_eph_pk[32], attacker_eph_sk[32];
    sodchan_hello_t h;
    uint8_t t_hello[SODCHAN_T_HELLO_LEN];
    uint8_t body[SODCHAN_HELLO_BODY_LEN];
    size_t blen = 0, flen = 0;

    assert(crypto_kx_keypair(attacker_eph_pk, attacker_eph_sk) == 0);

    memset(&h, 0, sizeof(h));
    h.proto_version = SODCHAN_PROTO_VERSION;
    h.suite_id = SODCHAN_SUITE_V1;
    h.role = SODCHAN_ROLE_SERVER;
    memcpy(h.eph_pk, attacker_eph_pk, 32);
    memcpy(h.id_pk, server_id_pk, 32);

    assert(sodchan_wire_build_t_hello(SODCHAN_PROTO_VERSION, SODCHAN_SUITE_V1,
                                      client_eph, attacker_eph_pk, server_id_pk,
                                      t_hello) == SODCHAN_OK);
    /* Sign with attacker identity sk, not real server — or wrong key entirely */
    assert(crypto_sign_detached(h.id_sig, NULL, t_hello, SODCHAN_T_HELLO_LEN,
                                attacker_sk) == 0);

    assert(sodchan_wire_hello_encode(&h, body, sizeof(body), &blen) == SODCHAN_OK);
    assert(sodchan_wire_frame_encode(body, blen, out, out_cap, &flen) ==
           SODCHAN_OK);
    return flen;
}

static void extract_client_eph_from_hello_frame(const uint8_t *frame, size_t flen,
                                                uint8_t eph_out[32])
{
    size_t consumed = 0;
    const uint8_t *body = NULL;
    size_t blen = 0;
    sodchan_hello_t h;

    assert(sodchan_wire_frame_parse(frame, flen, &consumed, &body, &blen) ==
           SODCHAN_OK);
    assert(sodchan_wire_hello_decode(body, blen, &h) == SODCHAN_OK);
    memcpy(eph_out, h.eph_pk, 32);
}

int main(void)
{
    uint8_t real_server_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t real_server_sk[SODCHAN_SECKEY_BYTES];
    uint8_t attacker_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t attacker_sk[SODCHAN_SECKEY_BYTES];
    sodchan_config_t ccfg;
    sodchan_ctx_t *c;
    uint8_t client_hello[512];
    uint8_t forged[512];
    size_t n, forged_len;
    uint8_t client_eph[32];
    sodchan_event_t ev;
    int saw_error = 0;

    printf("libsodchan MITM pin test (PR-4 K16)...\n");
    assert(sodium_init() >= 0);

    assert(sodchan_keygen_device(real_server_pk, real_server_sk) == SODCHAN_OK);
    assert(sodchan_keygen_device(attacker_pk, attacker_sk) == SODCHAN_OK);

    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.server_id_pk = real_server_pk; /* client pins the real server */

    c = sodchan_create(SODCHAN_ROLE_CLIENT, &ccfg);
    assert(c);
    assert(sodchan_current_state(c) == SODCHAN_STATE_HELLO);

    n = sodchan_get_output(c, client_hello, sizeof(client_hello));
    assert(n > 0);
    extract_client_eph_from_hello_frame(client_hello, n, client_eph);

    /* MITM: correct pin pk on wire, signature with attacker sk, substituted eph */
    forged_len = build_forged_server_hello_frame(client_eph, real_server_pk,
                                                 attacker_sk, forged,
                                                 sizeof(forged));
    assert(forged_len > 0);

    assert(sodchan_feed_input(c, forged, forged_len) == forged_len);
    assert(sodchan_current_state(c) == SODCHAN_STATE_ERROR);

    while (sodchan_next_event(c, &ev)) {
        if (ev.type == SODCHAN_EVENT_ERROR) {
            saw_error = 1;
            assert(ev.u.error.code == SODCHAN_ERR_CRYPTO ||
                   ev.u.error.code == SODCHAN_ERR_PROTOCOL);
        }
        /* Must not complete KX */
        assert(ev.type != SODCHAN_EVENT_KX_COMPLETE);
        assert(ev.type != SODCHAN_EVENT_AUTHENTICATED);
    }
    assert(saw_error);

    printf("  PASS: MITM with pinned pk + wrong sig rejected pre-AUTH\n");

    /* Also: wrong pin pk entirely */
    {
        sodchan_ctx_t *c2;
        sodchan_config_t c2cfg;
        uint8_t other_pk[SODCHAN_PUBKEY_BYTES], other_sk[SODCHAN_SECKEY_BYTES];
        uint8_t hello2[512], frame2[512];
        size_t n2, f2;
        uint8_t eph2[32];
        sodchan_hello_t h;
        uint8_t body[SODCHAN_HELLO_BODY_LEN], t[SODCHAN_T_HELLO_LEN];
        size_t bl = 0;

        assert(sodchan_keygen_device(other_pk, other_sk) == SODCHAN_OK);
        memset(&c2cfg, 0, sizeof(c2cfg));
        c2cfg.server_id_pk = real_server_pk;
        c2 = sodchan_create(SODCHAN_ROLE_CLIENT, &c2cfg);
        assert(c2);
        n2 = sodchan_get_output(c2, hello2, sizeof(hello2));
        extract_client_eph_from_hello_frame(hello2, n2, eph2);

        /* Honest signature for other_pk identity, but pin is real_server_pk */
        memset(&h, 0, sizeof(h));
        h.proto_version = SODCHAN_PROTO_VERSION;
        h.suite_id = SODCHAN_SUITE_V1;
        h.role = SODCHAN_ROLE_SERVER;
        assert(crypto_kx_keypair(h.eph_pk, t) == 0); /* t reused as sk scratch */
        {
            uint8_t eph_sk[32];
            memcpy(eph_sk, t, 32);
            memcpy(h.id_pk, other_pk, 32);
            assert(sodchan_wire_build_t_hello(1, 1, eph2, h.eph_pk, other_pk,
                                              t) == SODCHAN_OK);
            assert(crypto_sign_detached(h.id_sig, NULL, t, SODCHAN_T_HELLO_LEN,
                                        other_sk) == 0);
            (void)eph_sk;
        }
        assert(sodchan_wire_hello_encode(&h, body, sizeof(body), &bl) ==
               SODCHAN_OK);
        assert(sodchan_wire_frame_encode(body, bl, frame2, sizeof(frame2), &f2) ==
               SODCHAN_OK);
        assert(sodchan_feed_input(c2, frame2, f2) == f2);
        assert(sodchan_current_state(c2) == SODCHAN_STATE_ERROR);
        sodchan_destroy(c2);
        printf("  PASS: pin mismatch rejected\n");
    }

    sodchan_destroy(c);
    printf("libsodchan MITM pin test PASSED.\n");
    return 0;
}
