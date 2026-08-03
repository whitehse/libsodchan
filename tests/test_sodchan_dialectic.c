/**
 * @file test_sodchan_dialectic.c
 * @brief Client↔server pump: HELLO → KX → AUTH → READY.
 */

#include "sodchan.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int pump_once(sodchan_ctx_t *a, sodchan_ctx_t *b)
{
    uint8_t buf[8192];
    size_t n;
    int moved = 0;

    n = sodchan_get_output(a, buf, sizeof(buf));
    if (n > 0) {
        size_t c = sodchan_feed_input(b, buf, n);
        assert(c == n);
        moved = 1;
    }
    n = sodchan_get_output(b, buf, sizeof(buf));
    if (n > 0) {
        size_t c = sodchan_feed_input(a, buf, n);
        assert(c == n);
        moved = 1;
    }
    return moved;
}

int main(void)
{
    uint8_t server_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t server_sk[SODCHAN_SECKEY_BYTES];
    uint8_t client_pk[SODCHAN_PUBKEY_BYTES];
    uint8_t client_sk[SODCHAN_SECKEY_BYTES];
    sodchan_config_t scfg, ccfg;
    sodchan_ctx_t *s, *c;
    int i;
    int s_hello = 0, s_kx = 0, s_auth_dev = 0, s_authed = 0;
    int c_hello = 0, c_kx = 0, c_authed = 0;

    printf("libsodchan dialectic test (handshake + auth)...\n");

    assert(sodchan_keygen_device(server_pk, server_sk) == SODCHAN_OK);
    assert(sodchan_keygen_device(client_pk, client_sk) == SODCHAN_OK);

    memset(&scfg, 0, sizeof(scfg));
    scfg.server_id_pk = server_pk;
    scfg.server_id_sk = server_sk;

    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.server_id_pk = server_pk;
    ccfg.client_id_pk = client_pk;
    ccfg.client_id_sk = client_sk;
    ccfg.client_username = "lab";
    ccfg.client_device_id = "dialectic";

    s = sodchan_create(SODCHAN_ROLE_SERVER, &scfg);
    c = sodchan_create(SODCHAN_ROLE_CLIENT, &ccfg);
    assert(s && c);

    for (i = 0; i < 64; i++) {
        pump_once(c, s);
        pump_once(s, c);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_HELLO_RECEIVED) {
                    s_hello = 1;
                } else if (ev.type == SODCHAN_EVENT_KX_COMPLETE) {
                    s_kx = 1;
                } else if (ev.type == SODCHAN_EVENT_AUTH_DEVICE) {
                    s_auth_dev = 1;
                    assert(ev.u.auth.sig_ok == 1);
                    assert(sodchan_auth_decide(s, 1) == SODCHAN_OK);
                } else if (ev.type == SODCHAN_EVENT_AUTHENTICATED) {
                    s_authed = 1;
                } else if (ev.type == SODCHAN_EVENT_ERROR) {
                    fprintf(stderr, "server ERROR: %s\n", ev.u.error.message);
                    assert(0);
                }
            }
            while (sodchan_next_event(c, &ev)) {
                if (ev.type == SODCHAN_EVENT_HELLO_RECEIVED) {
                    c_hello = 1;
                } else if (ev.type == SODCHAN_EVENT_KX_COMPLETE) {
                    c_kx = 1;
                } else if (ev.type == SODCHAN_EVENT_AUTHENTICATED) {
                    c_authed = 1;
                } else if (ev.type == SODCHAN_EVENT_ERROR) {
                    fprintf(stderr, "client ERROR: %s\n", ev.u.error.message);
                    assert(0);
                }
            }
        }
        if (sodchan_current_state(s) == SODCHAN_STATE_READY &&
            sodchan_current_state(c) == SODCHAN_STATE_READY && s_authed &&
            c_authed) {
            break;
        }
    }

    assert(s_hello && c_hello);
    assert(s_kx && c_kx);
    assert(s_auth_dev);
    assert(s_authed && c_authed);
    assert(sodchan_current_state(s) == SODCHAN_STATE_READY);
    assert(sodchan_current_state(c) == SODCHAN_STATE_READY);

    printf("  PASS: dialectic reaches READY (full auth)\n");
    sodchan_destroy(s);
    sodchan_destroy(c);
    printf("libsodchan dialectic test PASSED.\n");
    return 0;
}
