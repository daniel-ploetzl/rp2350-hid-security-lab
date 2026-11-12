/*
 * Login typist. See inc/login.h for the model.
 *
 *   The sequence to type is flattened once at the start into s_seq: the
 *   username, a newline, the password, a newline. Each pass sends one report,
 *   alternating a key down with its release, and advances only when the report
 *   was accepted. After the last key it waits LOGIN_WAIT_MS, then clears the
 *   buffer so the password does not linger in RAM.
 */

#include "login.h"
#include "hid_keymap.h"
#include "hid_assert.h"
#include "tusb.h"

#include <string.h>

#define REPORT_ID_KEYBOARD 1
#define LOGIN_WAIT_MS      15000u

typedef enum { LS_DONE, LS_KEYDOWN, LS_KEYUP, LS_WAIT } login_phase_t;

static login_phase_t s_phase = LS_DONE;
static char          s_seq[LOGIN_USER_MAX + LOGIN_PASS_MAX + 3];
static size_t        s_len;
static size_t        s_pos;
static uint32_t      s_wait_start;

void login_begin_from(const login_creds_t *lc)
{
    if (lc == NULL)
    {
        s_phase = LS_DONE;
        return;
    }

    size_t n = 0;
    for (size_t i = 0; i < LOGIN_USER_MAX && lc->user[i] != '\0'; i++)
        s_seq[n++] = lc->user[i];
    s_seq[n++] = '\n';
    for (size_t i = 0; i < LOGIN_PASS_MAX && lc->pass[i] != '\0'; i++)
        s_seq[n++] = lc->pass[i];
    s_seq[n++] = '\n';

    HID_ASSERT(n <= sizeof s_seq);
    s_len   = n;
    s_pos   = 0;
    s_phase = LS_KEYDOWN;
}

void login_begin(void)
{
    login_begin_from(login_read());
}

void login_task(uint32_t now_ms)
{
    switch (s_phase)
    {
        case LS_KEYDOWN:
            if (s_pos >= s_len)
            {
                s_wait_start = now_ms;
                s_phase = LS_WAIT;
                return;
            }
            if (!tud_hid_ready())
                return;
            {
                char    c = s_seq[s_pos];
                uint8_t usage;
                uint8_t mod;

                if (c == '\n')
                {
                    usage = HID_KEY_ENTER;
                    mod   = 0;
                }
                else if (!hid_key_for(c, &usage, &mod))
                {
                    /* write_config rejects untypeable characters, so this is
                     * defensive: skip it rather than send a wrong key. */
                    s_pos++;
                    return;
                }

                uint8_t kc[6] = { usage, 0, 0, 0, 0, 0 };
                if (tud_hid_keyboard_report(REPORT_ID_KEYBOARD, mod, kc))
                    s_phase = LS_KEYUP;
            }
            return;

        case LS_KEYUP:
            if (!tud_hid_ready())
                return;
            /* Release every key before the next one, so none auto-repeats. */
            if (tud_hid_keyboard_report(REPORT_ID_KEYBOARD, 0, NULL))
            {
                s_pos++;
                s_phase = LS_KEYDOWN;
            }
            return;

        case LS_WAIT:
            if (now_ms - s_wait_start >= LOGIN_WAIT_MS)
            {
                memset(s_seq, 0, sizeof s_seq);
                s_phase = LS_DONE;
            }
            return;

        case LS_DONE:
        default:
            return;
    }
}

bool login_in_progress(void)
{
    return s_phase != LS_DONE;
}

bool login_is_done(void)
{
    return s_phase == LS_DONE;
}
