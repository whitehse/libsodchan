/**
 * @file test_sodchan_dialectic.c
 * @brief PR-4: client↔server buffer pump through HELLO + KX + SS headers → AUTH.
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

static void drain_events(sodchan_ctx_t *ctx, int *saw_hello, int *saw_kx)
{
    sodchan_event_t ev;

    while (sodchan_next_event(ctx, &ev)) {
        if (ev.type == SODCHAN_EVENT_HELLO_RECEIVED) {
            *saw_hello = 1;
        } else if (ev.type == SODCHAN_EVENT_KX_COMPLETE) {
            *saw_kx = 1;
        } else if (ev.type == SODCHAN_EVENT_ERROR) {
            fprintf(stderr, "unexpected ERROR: %s (%d)\n", ev.u.error.message,
                    ev.u.error.code);
            assert(0);
        }
    }
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
    int s_hello = 0, s_kx = 0, c_hello = 0, c_kx = 0;

    printf("libsodchan dialectic test (PR-4 handshake)...\n");

    assert(sodchan_keygen_device(server_pk, server_sk) == SODCHAN_OK);
    assert(sodchan_keygen_device(client_pk, client_sk) == SODCHAN_OK);

    memset(&scfg, 0, sizeof(scfg));
    scfg.server_id_pk = server_pk;
    scfg.server_id_sk = server_sk;

    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.server_id_pk = server_pk; /* pin */
    ccfg.client_id_pk = client_pk;
    ccfg.client_id_sk = client_sk;

    s = sodchan_create(SODCHAN_ROLE_SERVER, &scfg);
    c = sodchan_create(SODCHAN_ROLE_CLIENT, &ccfg);
    assert(s && c);
    assert(sodchan_current_state(s) == SODCHAN_STATE_HELLO);
    assert(sodchan_current_state(c) == SODCHAN_STATE_HELLO);

    for (i = 0; i < 32; i++) {
        if (!pump_once(c, s) && !pump_once(s, c)) {
            /* allow one more drain of residual */
        }
        drain_events(s, &s_hello, &s_kx);
        drain_events(c, &c_hello, &c_kx);
        if (sodchan_current_state(s) == SODCHAN_STATE_AUTH &&
            sodchan_current_state(c) == SODCHAN_STATE_AUTH && s_kx && c_kx) {
            break;
        }
    }

    assert(sodchan_current_state(s) == SODCHAN_STATE_AUTH);
    assert(sodchan_current_state(c) == SODCHAN_STATE_AUTH);
    assert(s_hello && c_hello);
    assert(s_kx && c_kx);

    printf("  PASS: dialectic reaches AUTH (HELLO + KX + secretstream headers)\n");

    sodchan_destroy(s);
    sodchan_destroy(c);
    printf("libsodchan dialectic test PASSED.\n");
    return 0;
}
