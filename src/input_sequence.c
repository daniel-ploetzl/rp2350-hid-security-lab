/*
 * Stored input sequence state machine.
 *
 *   The sequence to type is flattened once at the start into s_seq. After
 *   the host-session wait it appends the final configured action. Each pass
 *   sends one report, alternating a key down with its release, and advances
 *   only when the report was accepted. After the last key it clears the buffer
 *   so the sequence does not linger in RAM.
 */

#include "input_tasks.h"
#include "hid_keymap.h"
#include "hid_assert.h"
#include "secure_store.h"
#include "tusb.h"
#include <string.h>

#define REPORT_ID_KEYBOARD 1
#define INPUT_SEQUENCE_ACTION_DELAY_MS      15000u
#define INPUT_SEQUENCE_USB_SETTLE_MS 2000u
typedef enum { IS_DONE, IS_USB_WAIT, IS_LINE_KEYDOWN, IS_KEYUP, IS_ACTION_WAIT, IS_ACTION_KEYDOWN } input_sequence_phase_t;

static input_sequence_phase_t s_phase = IS_DONE;
static char          s_seq[INPUT_SEQUENCE_LINE1_MAX + INPUT_SEQUENCE_LINE2_MAX + INPUT_SEQUENCE_ACTION_MAX + 3];
static size_t        s_len;
static size_t        s_prefix_len;
static size_t        s_pos;
static uint32_t      s_wait_start;
static input_sequence_phase_t s_keyup_next;
static bool          s_usb_wait_started;

void input_sequence_begin_from(const input_sequence_config_t *sequence)
{
    if (sequence == NULL)
    {
        memset(s_seq, 0, sizeof s_seq);
        s_len = 0;
        s_pos = 0;
        s_phase = IS_DONE;
        return;
    }

    size_t n = 0;
    for (size_t i = 0; i < INPUT_SEQUENCE_LINE1_MAX && sequence->line1[i] != '\0'; i++)
        s_seq[n++] = sequence->line1[i];
    s_seq[n++] = '\n';
    for (size_t i = 0; i < INPUT_SEQUENCE_LINE2_MAX && sequence->line2[i] != '\0'; i++)
        s_seq[n++] = sequence->line2[i];
    s_seq[n++] = '\n';
    s_prefix_len = n;
    for (size_t i = 0; i < INPUT_SEQUENCE_ACTION_MAX && sequence->action[i] != '\0'; i++)
        s_seq[n++] = sequence->action[i];
    s_seq[n++] = '\n';

    HID_ASSERT(n <= sizeof s_seq);
    s_len   = n;
    s_pos   = 0;
    s_keyup_next = IS_LINE_KEYDOWN;
    s_usb_wait_started = false;
    s_phase = IS_USB_WAIT;
}

void input_sequence_begin(void)
{
    input_sequence_config_t sequence;
    const secure_record_t *record = (const secure_record_t *)INPUT_SEQUENCE_FLASH_ADDR;
    bool valid = secure_store_open(INPUT_SEQUENCE_FLASH_ADDR, record,
                                   &sequence, sizeof sequence) &&
                 input_sequence_valid(&sequence);
    input_sequence_begin_from(valid ? &sequence : NULL);
    secure_store_clear(&sequence, sizeof sequence);
}

void input_sequence_task(uint32_t now_ms)
{
    switch (s_phase)
    {
        case IS_USB_WAIT:
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
            if ((uint32_t)(now_ms - s_wait_start) >= INPUT_SEQUENCE_USB_SETTLE_MS)
                s_phase = IS_LINE_KEYDOWN;
            return;

        case IS_LINE_KEYDOWN:
            if (s_pos >= s_prefix_len)
            {
                s_wait_start = now_ms;
                s_phase = IS_ACTION_WAIT;
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
                    s_keyup_next = IS_LINE_KEYDOWN;
                    s_phase = IS_KEYUP;
                }
            }
            return;

        case IS_ACTION_KEYDOWN:
            if (s_pos >= s_len)
            {
                memset(s_seq, 0, sizeof s_seq);
                s_phase = IS_DONE;
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
                    s_keyup_next = IS_ACTION_KEYDOWN;
                    s_phase = IS_KEYUP;
                }
            }
            return;

        case IS_KEYUP:
            if (!tud_hid_ready())
                return;
            /* Release every key before the next one, so none auto-repeats. */
            if (tud_hid_keyboard_report(REPORT_ID_KEYBOARD, 0, NULL))
            {
                s_pos++;
                s_phase = s_keyup_next;
            }
            return;

        case IS_ACTION_WAIT:
            if (now_ms - s_wait_start >= INPUT_SEQUENCE_ACTION_DELAY_MS)
            {
                s_phase = IS_ACTION_KEYDOWN;
            }
            return;

        case IS_DONE:
        default:
            return;
    }
}

bool input_sequence_in_progress(void)
{
    return s_phase != IS_DONE;
}

bool input_sequence_is_done(void)
{
    return s_phase == IS_DONE;
}
