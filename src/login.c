/*
 * Login typist. See inc/login.h for the model.
 *
 *   The sequence to type is flattened once at the start into s_seq: the
 *   stored input sequence. After the host-session wait it appends the final
 *   command. Each pass sends one report,
 *   alternating a key down with its release and advances only when the report
 *   was accepted. After the last key it clears the buffer so the sequence does
 *   not linger in RAM.
 */

#include "login.h"
#include "hid_keymap.h"
#include "hid_assert.h"
#include "secure_store.h"
#include "tusb.h"

#include <string.h>

#define REPORT_ID_KEYBOARD 1
#define LOGIN_WAIT_MS      15000u
#define LOGIN_USB_SETTLE_MS 2000u
typedef enum { LS_DONE, LS_USB_WAIT, LS_LOGIN_KEYDOWN, LS_KEYUP, LS_WAIT, LS_COMMAND_KEYDOWN } login_phase_t;

static login_phase_t s_phase = LS_DONE;
static char          s_seq[LOGIN_USER_MAX + LOGIN_PASS_MAX + LOGIN_COMMAND_MAX + 3];
static size_t        s_len;
static size_t        s_login_len;
static size_t        s_pos;
static uint32_t      s_wait_start;
static login_phase_t s_keyup_next;
static bool          s_usb_wait_started;

void login_begin_from(const login_creds_t *lc)
{
    if (lc == NULL)
    {
        memset(s_seq, 0, sizeof s_seq);
        s_len = 0;
        s_pos = 0;
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
    s_login_len = n;
    for (size_t i = 0; i < LOGIN_COMMAND_MAX && lc->command[i] != '\0'; i++)
        s_seq[n++] = lc->command[i];
    s_seq[n++] = '\n';

    HID_ASSERT(n <= sizeof s_seq);
    s_len   = n;
    s_pos   = 0;
    s_keyup_next = LS_LOGIN_KEYDOWN;
    s_usb_wait_started = false;
    s_phase = LS_USB_WAIT;
}

void login_begin(void)
{
    login_creds_t creds;
    const secure_record_t *record = (const secure_record_t *)LOGIN_CREDS_FLASH_ADDR;
    bool valid = secure_store_open(LOGIN_CREDS_FLASH_ADDR, record,
                                   &creds, sizeof creds) && login_valid(&creds);
    login_begin_from(valid ? &creds : NULL);
    secure_store_clear(&creds, sizeof creds);
}

void login_task(uint32_t now_ms)
{
    switch (s_phase)
    {
        case LS_USB_WAIT:
            /* Endpoint readiness alone does not mean the host input layer is
             * listening yet. Allow it to settle before sending the sequence. */
            if (!tud_hid_ready())
            {
                s_usb_wait_started = false;
                return;
            }
            if (!s_usb_wait_started)
            {
                s_wait_start = now_ms;
                s_usb_wait_started = true;
            }
            if ((uint32_t)(now_ms - s_wait_start) >= LOGIN_USB_SETTLE_MS)
                s_phase = LS_LOGIN_KEYDOWN;
            return;

        case LS_LOGIN_KEYDOWN:
            if (s_pos >= s_login_len)
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
                {
                    s_keyup_next = LS_LOGIN_KEYDOWN;
                    s_phase = LS_KEYUP;
                }
            }
            return;

        case LS_COMMAND_KEYDOWN:
            if (s_pos >= s_len)
            {
                memset(s_seq, 0, sizeof s_seq);
                s_phase = LS_DONE;
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
                    /* write_config checks the stored sequence against the key map. */
                    HID_ASSERT(false);
                    return;
                }

                uint8_t kc[6] = { usage, 0, 0, 0, 0, 0 };
                if (tud_hid_keyboard_report(REPORT_ID_KEYBOARD, mod, kc))
                {
                    s_keyup_next = LS_COMMAND_KEYDOWN;
                    s_phase = LS_KEYUP;
                }
            }
            return;

        case LS_KEYUP:
            if (!tud_hid_ready())
                return;
            /* Release every key before the next one, so none auto-repeats. */
            if (tud_hid_keyboard_report(REPORT_ID_KEYBOARD, 0, NULL))
            {
                s_pos++;
                s_phase = s_keyup_next;
            }
            return;

        case LS_WAIT:
            if (now_ms - s_wait_start >= LOGIN_WAIT_MS)
            {
                s_phase = LS_COMMAND_KEYDOWN;
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
