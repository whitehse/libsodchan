/**
 * @file test_sodchan_auth.c
 * @brief PR-5: AUTH_DEVICE, auth_decide, AUTH_OK/FAIL over secretstream.
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
        assert(sodchan_feed_input(b, buf, n) == n);
        moved = 1;
    }
    n = sodchan_get_output(b, buf, sizeof(buf));
    if (n > 0) {
        assert(sodchan_feed_input(a, buf, n) == n);
        moved = 1;
    }
    return moved;
}

static void setup_pair(sodchan_ctx_t **s_out, sodchan_ctx_t **c_out,
                       uint8_t server_pk[32], uint8_t server_sk[64],
                       uint8_t client_pk[32], uint8_t client_sk[64],
                       const char *user, const char *device)
{
    sodchan_config_t scfg, ccfg;

    assert(sodchan_keygen_device(server_pk, server_sk) == SODCHAN_OK);
    assert(sodchan_keygen_device(client_pk, client_sk) == SODCHAN_OK);

    memset(&scfg, 0, sizeof(scfg));
    scfg.server_id_pk = server_pk;
    scfg.server_id_sk = server_sk;

    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.server_id_pk = server_pk;
    ccfg.client_id_pk = client_pk;
    ccfg.client_id_sk = client_sk;
    ccfg.client_username = user;
    ccfg.client_device_id = device;

    *s_out = sodchan_create(SODCHAN_ROLE_SERVER, &scfg);
    *c_out = sodchan_create(SODCHAN_ROLE_CLIENT, &ccfg);
    assert(*s_out && *c_out);
}

static int run_to_auth_device(sodchan_ctx_t *c, sodchan_ctx_t *s,
                              sodchan_event_t *auth_ev)
{
    int i;
    int saw = 0;

    for (i = 0; i < 64; i++) {
        pump_once(c, s);
        pump_once(s, c);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_AUTH_DEVICE) {
                    *auth_ev = ev;
                    saw = 1;
                }
                assert(ev.type != SODCHAN_EVENT_ERROR);
            }
            while (sodchan_next_event(c, &ev)) {
                assert(ev.type != SODCHAN_EVENT_ERROR);
                assert(ev.type != SODCHAN_EVENT_AUTH_FAILED);
            }
        }
        if (saw) {
            return 1;
        }
    }
    return 0;
}

static void test_accept_to_ready(void)
{
    uint8_t spk[32], ssk[64], cpk[32], csk[64];
    sodchan_ctx_t *s, *c;
    sodchan_event_t adev;
    int c_ok = 0, s_ok = 0;
    int i;

    setup_pair(&s, &c, spk, ssk, cpk, csk, "alice", "phone-1");
    assert(run_to_auth_device(c, s, &adev));
    assert(adev.u.auth.sig_ok == 1);
    assert(strcmp(adev.u.auth.username, "alice") == 0);
    assert(strcmp(adev.u.auth.device_id, "phone-1") == 0);
    assert(memcmp(adev.u.auth.peer_id_pk, cpk, 32) == 0);
    assert(strncmp(adev.u.auth.fingerprint_sha256, "SHA256:", 7) == 0);

    assert(sodchan_auth_decide_ex(s, 1, (const uint8_t *)"{\"sub\":\"alice\"}",
                                  15) == SODCHAN_OK);
    assert(sodchan_auth_decide(s, 1) == SODCHAN_ERR_STATE); /* second call */

    for (i = 0; i < 16; i++) {
        pump_once(s, c);
        pump_once(c, s);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(c, &ev)) {
                if (ev.type == SODCHAN_EVENT_AUTHENTICATED) {
                    c_ok = 1;
                }
                assert(ev.type != SODCHAN_EVENT_ERROR);
            }
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_AUTHENTICATED) {
                    s_ok = 1;
                }
                assert(ev.type != SODCHAN_EVENT_ERROR);
            }
        }
        if (c_ok && s_ok &&
            sodchan_current_state(c) == SODCHAN_STATE_READY &&
            sodchan_current_state(s) == SODCHAN_STATE_READY) {
            break;
        }
    }

    assert(c_ok && s_ok);
    assert(sodchan_current_state(c) == SODCHAN_STATE_READY);
    assert(sodchan_current_state(s) == SODCHAN_STATE_READY);
    printf("  PASS: AUTH_DEVICE + decide(1) → READY both sides\n");
    sodchan_destroy(s);
    sodchan_destroy(c);
}

static void test_policy_reject(void)
{
    uint8_t spk[32], ssk[64], cpk[32], csk[64];
    sodchan_ctx_t *s, *c;
    sodchan_event_t adev;
    int c_fail = 0;
    int i;

    setup_pair(&s, &c, spk, ssk, cpk, csk, "bob", "dev");
    assert(run_to_auth_device(c, s, &adev));
    assert(sodchan_auth_decide(s, 0) == SODCHAN_OK);

    for (i = 0; i < 16; i++) {
        pump_once(s, c);
        pump_once(c, s);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(c, &ev)) {
                if (ev.type == SODCHAN_EVENT_AUTH_FAILED) {
                    c_fail = 1;
                }
            }
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_AUTH_FAILED) {
                    assert(ev.u.error.code == SODCHAN_AUTH_REASON_POLICY);
                }
            }
        }
        if (sodchan_current_state(c) == SODCHAN_STATE_ERROR &&
            sodchan_current_state(s) == SODCHAN_STATE_ERROR) {
            break;
        }
    }
    assert(c_fail);
    assert(sodchan_current_state(c) == SODCHAN_STATE_ERROR);
    assert(sodchan_current_state(s) == SODCHAN_STATE_ERROR);
    printf("  PASS: decide(0) → AUTH_FAIL both ERROR\n");
    sodchan_destroy(s);
    sodchan_destroy(c);
}

static void test_bad_device_sig(void)
{
    uint8_t spk[32], ssk[64], cpk[32], csk[64];
    uint8_t wrong_sk[64], wrong_pk[32];
    sodchan_config_t scfg, ccfg;
    sodchan_ctx_t *s, *c;
    int i;
    int saw_fail = 0;

    assert(sodchan_keygen_device(spk, ssk) == SODCHAN_OK);
    assert(sodchan_keygen_device(cpk, csk) == SODCHAN_OK);
    assert(sodchan_keygen_device(wrong_pk, wrong_sk) == SODCHAN_OK);

    memset(&scfg, 0, sizeof(scfg));
    scfg.server_id_pk = spk;
    scfg.server_id_sk = ssk;

    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.server_id_pk = spk;
    /* Advertise cpk but sign with wrong_sk → verify fails against cpk */
    ccfg.client_id_pk = cpk;
    ccfg.client_id_sk = wrong_sk;
    ccfg.client_username = "eve";

    s = sodchan_create(SODCHAN_ROLE_SERVER, &scfg);
    c = sodchan_create(SODCHAN_ROLE_CLIENT, &ccfg);
    assert(s && c);

    for (i = 0; i < 64; i++) {
        pump_once(c, s);
        pump_once(s, c);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_AUTH_FAILED) {
                    assert(ev.u.error.code == SODCHAN_AUTH_REASON_BAD_SIG);
                    saw_fail = 1;
                }
                /* Must not ask host to decide */
                assert(ev.type != SODCHAN_EVENT_AUTH_DEVICE);
            }
            while (sodchan_next_event(c, &ev)) {
                (void)ev;
            }
        }
        if (sodchan_current_state(s) == SODCHAN_STATE_ERROR) {
            break;
        }
    }
    assert(saw_fail);
    assert(sodchan_current_state(s) == SODCHAN_STATE_ERROR);
    printf("  PASS: bad AUTH_DEVICE sig → AUTH_FAIL, no auth_decide\n");
    sodchan_destroy(s);
    sodchan_destroy(c);
}

int main(void)
{
    printf("libsodchan auth test (PR-5)...\n");
    test_accept_to_ready();
    test_policy_reject();
    test_bad_device_sig();
    printf("libsodchan auth test PASSED.\n");
    return 0;
}
