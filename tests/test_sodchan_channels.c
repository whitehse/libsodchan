/**
 * @file test_sodchan_channels.c
 * @brief PR-6: channel open/data/window/eof/close over READY session.
 */

#include "sodchan.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int pump_once(sodchan_ctx_t *a, sodchan_ctx_t *b)
{
    uint8_t buf[131072];
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

static void pump_n(sodchan_ctx_t *c, sodchan_ctx_t *s, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        pump_once(c, s);
        pump_once(s, c);
    }
}

static void handshake_ready(sodchan_ctx_t **s_out, sodchan_ctx_t **c_out,
                            uint32_t init_window, uint32_t max_packet)
{
    static uint8_t spk[32], ssk[64], cpk[32], csk[64];
    sodchan_config_t scfg, ccfg;
    sodchan_ctx_t *s, *c;
    int i;
    int s_ready = 0, c_ready = 0;

    assert(sodchan_keygen_device(spk, ssk) == SODCHAN_OK);
    assert(sodchan_keygen_device(cpk, csk) == SODCHAN_OK);

    memset(&scfg, 0, sizeof(scfg));
    scfg.server_id_pk = spk;
    scfg.server_id_sk = ssk;
    scfg.initial_window = init_window;
    scfg.max_packet = max_packet;

    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.server_id_pk = spk;
    ccfg.client_id_pk = cpk;
    ccfg.client_id_sk = csk;
    ccfg.client_username = "ch";
    ccfg.client_device_id = "t1";
    ccfg.initial_window = init_window;
    ccfg.max_packet = max_packet;

    s = sodchan_create(SODCHAN_ROLE_SERVER, &scfg);
    c = sodchan_create(SODCHAN_ROLE_CLIENT, &ccfg);
    assert(s && c);

    for (i = 0; i < 64; i++) {
        pump_once(c, s);
        pump_once(s, c);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_AUTH_DEVICE) {
                    assert(sodchan_auth_decide(s, 1) == SODCHAN_OK);
                }
            }
            while (sodchan_next_event(c, &ev)) {
                (void)ev;
            }
        }
        if (sodchan_current_state(s) == SODCHAN_STATE_READY) {
            s_ready = 1;
        }
        if (sodchan_current_state(c) == SODCHAN_STATE_READY) {
            c_ready = 1;
        }
        if (s_ready && c_ready) {
            break;
        }
    }
    assert(s_ready && c_ready);
    *s_out = s;
    *c_out = c;
}

static void test_open_send_recv(void)
{
    sodchan_ctx_t *s, *c;
    uint32_t cid = 0;
    int i;
    int opened_c = 0, opened_s = 0, got_data = 0;

    handshake_ready(&s, &c, 256 * 1024, 64 * 1024);

    assert(sodchan_channel_open(c, SODCHAN_CHANNEL_EDGE_TELEMETRY, &cid) ==
           SODCHAN_OK);

    for (i = 0; i < 32; i++) {
        pump_n(c, s, 1);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_CHANNEL_OPEN) {
                    assert(strcmp(ev.u.channel.name,
                                  SODCHAN_CHANNEL_EDGE_TELEMETRY) == 0);
                    assert(sodchan_channel_accept(s, ev.u.channel.channel_id,
                                                  1) == SODCHAN_OK);
                } else if (ev.type == SODCHAN_EVENT_CHANNEL_OPENED) {
                    opened_s = 1;
                } else if (ev.type == SODCHAN_EVENT_CHANNEL_DATA) {
                    assert(ev.u.data.len == 5);
                    assert(memcmp(ev.u.data.data, "hello", 5) == 0);
                    got_data = 1;
                    assert(sodchan_channel_window_adjust(
                               s, ev.u.data.channel_id, 5) == SODCHAN_OK);
                }
            }
            while (sodchan_next_event(c, &ev)) {
                if (ev.type == SODCHAN_EVENT_CHANNEL_OPENED) {
                    opened_c = 1;
                    assert(ev.u.channel.channel_id == cid);
                }
            }
        }
        if (opened_c && opened_s &&
            sodchan_channel_window_avail(c, cid) > 0) {
            break;
        }
    }
    assert(opened_c && opened_s);

    assert(sodchan_channel_send(c, cid, (const uint8_t *)"hello", 5) ==
           SODCHAN_OK);

    for (i = 0; i < 16; i++) {
        pump_n(c, s, 1);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_CHANNEL_DATA) {
                    assert(ev.u.data.len == 5);
                    assert(memcmp(ev.u.data.data, "hello", 5) == 0);
                    got_data = 1;
                }
            }
            while (sodchan_next_event(c, &ev)) {
                (void)ev;
            }
        }
        if (got_data) {
            break;
        }
    }
    assert(got_data);

    assert(sodchan_channel_eof(c, cid) == SODCHAN_OK);
    pump_n(c, s, 4);
    {
        sodchan_event_t ev;
        int saw_eof = 0;
        while (sodchan_next_event(s, &ev)) {
            if (ev.type == SODCHAN_EVENT_CHANNEL_EOF) {
                saw_eof = 1;
            }
        }
        assert(saw_eof);
    }
    assert(sodchan_channel_close(c, cid) == SODCHAN_OK);
    pump_n(c, s, 4);

    printf("  PASS: open/accept/send/recv/eof/close\n");
    sodchan_destroy(s);
    sodchan_destroy(c);
}

static void test_flow_control_window(void)
{
    sodchan_ctx_t *s, *c;
    uint32_t cid = 0;
    int i;
    int opened = 0;

    /* Tiny windows: 8-byte initial window */
    handshake_ready(&s, &c, 8, 8);

    assert(sodchan_channel_open(c, "edge-control", &cid) == SODCHAN_OK);
    for (i = 0; i < 32; i++) {
        pump_n(c, s, 1);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_CHANNEL_OPEN) {
                    assert(sodchan_channel_accept(s, ev.u.channel.channel_id,
                                                  1) == SODCHAN_OK);
                }
            }
            while (sodchan_next_event(c, &ev)) {
                if (ev.type == SODCHAN_EVENT_CHANNEL_OPENED) {
                    opened = 1;
                }
            }
        }
        if (opened) {
            break;
        }
    }
    assert(opened);
    assert(sodchan_channel_window_avail(c, cid) == 8);

    /* 8-byte send OK */
    assert(sodchan_channel_send(c, cid, (const uint8_t *)"12345678", 8) ==
           SODCHAN_OK);
    assert(sodchan_channel_window_avail(c, cid) == 0);
    /* Exhausted */
    assert(sodchan_channel_send(c, cid, (const uint8_t *)"x", 1) ==
           SODCHAN_ERR_WINDOW);

    pump_n(c, s, 8);
    {
        sodchan_event_t ev;
        uint32_t sid = 0;
        while (sodchan_next_event(s, &ev)) {
            if (ev.type == SODCHAN_EVENT_CHANNEL_DATA) {
                sid = ev.u.data.channel_id;
                assert(ev.u.data.len == 8);
                assert(sodchan_channel_window_adjust(s, sid, 16) == SODCHAN_OK);
            }
        }
    }
    pump_n(c, s, 8);
    {
        sodchan_event_t ev;
        int saw_win = 0;
        while (sodchan_next_event(c, &ev)) {
            if (ev.type == SODCHAN_EVENT_CHANNEL_WINDOW) {
                assert(ev.u.window.bytes_added == 16);
                assert(ev.u.window.window_avail >= 16);
                saw_win = 1;
            }
        }
        assert(saw_win);
    }
    assert(sodchan_channel_window_avail(c, cid) >= 16);
    assert(sodchan_channel_send(c, cid, (const uint8_t *)"ok", 2) == SODCHAN_OK);

    printf("  PASS: flow control WINDOW / ERR_WINDOW\n");
    sodchan_destroy(s);
    sodchan_destroy(c);
}

static void test_reject_not_allowed(void)
{
    sodchan_ctx_t *s, *c;
    uint32_t cid = 0;
    sodchan_config_t scfg, ccfg;
    uint8_t spk[32], ssk[64], cpk[32], csk[64];
    int i, fail = 0;

    assert(sodchan_keygen_device(spk, ssk) == SODCHAN_OK);
    assert(sodchan_keygen_device(cpk, csk) == SODCHAN_OK);

    memset(&scfg, 0, sizeof(scfg));
    scfg.server_id_pk = spk;
    scfg.server_id_sk = ssk;
    scfg.allowed_channels = "edge-telemetry";

    memset(&ccfg, 0, sizeof(ccfg));
    ccfg.server_id_pk = spk;
    ccfg.client_id_pk = cpk;
    ccfg.client_id_sk = csk;
    ccfg.allowed_channels = "edge-telemetry,edge-control";
    ccfg.client_username = "x";

    s = sodchan_create(SODCHAN_ROLE_SERVER, &scfg);
    c = sodchan_create(SODCHAN_ROLE_CLIENT, &ccfg);
    assert(s && c);
    for (i = 0; i < 64; i++) {
        pump_once(c, s);
        pump_once(s, c);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(s, &ev)) {
                if (ev.type == SODCHAN_EVENT_AUTH_DEVICE) {
                    assert(sodchan_auth_decide(s, 1) == SODCHAN_OK);
                }
            }
            while (sodchan_next_event(c, &ev)) {
                (void)ev;
            }
        }
        if (sodchan_current_state(s) == SODCHAN_STATE_READY &&
            sodchan_current_state(c) == SODCHAN_STATE_READY) {
            break;
        }
    }

    /* Client may open edge-control locally, server rejects */
    assert(sodchan_channel_open(c, "edge-control", &cid) == SODCHAN_OK);
    for (i = 0; i < 16; i++) {
        pump_n(c, s, 1);
        {
            sodchan_event_t ev;
            while (sodchan_next_event(c, &ev)) {
                if (ev.type == SODCHAN_EVENT_CHANNEL_OPEN_FAIL) {
                    fail = 1;
                }
            }
            while (sodchan_next_event(s, &ev)) {
                /* Server should not emit OPEN for disallowed — auto OPEN_FAIL */
                assert(ev.type != SODCHAN_EVENT_CHANNEL_OPEN);
            }
        }
        if (fail) {
            break;
        }
    }
    assert(fail);
    printf("  PASS: allowlist rejects edge-control on server\n");
    sodchan_destroy(s);
    sodchan_destroy(c);
}

int main(void)
{
    printf("libsodchan channels test (PR-6)...\n");
    test_open_send_recv();
    test_flow_control_window();
    test_reject_not_allowed();
    printf("libsodchan channels test PASSED.\n");
    return 0;
}
