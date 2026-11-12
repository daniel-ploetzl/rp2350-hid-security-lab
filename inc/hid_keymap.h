/*
 * ASCII to USB HID key code map, German QWERTZ (DE) layout.
 *
 *   A USB keyboard sends positional key codes plus a modifier byte, and the
 *   host turns those into characters using its own layout. This table gives,
 *   for each printable ASCII character, the code and modifier that produce it
 *   when the host is set to German QWERTZ.
 *
 *   usage 0 means the character cannot be produced on this layout without a
 *   dead key, or is not ASCII. Callers treat that as "not typeable" rather
 *   than guess. Dead-key characters (^ ` and the accents) and the non-ASCII
 *   German characters (umlauts, ß, €, §) are deliberately left out.
 *
 *   Shared by the firmware, which types, and write_config, which validates a
 *   stored credential, so the two always agree on what can be typed.
 *
 *   Verify on the real host once: store a credential containing the symbols
 *   you use and watch them appear in a text field. The table is from the DE
 *   layout spec and has not been checked against your exact host.
 */

#ifndef HID_KEYMAP_H
#define HID_KEYMAP_H

#include <stdint.h>
#include <stdbool.h>

/* USB HID modifier bits. Left Shift for the shifted characters, Right Alt
 * (AltGr) for the third level such as @ and the brackets. */
#define HID_MOD_SHIFT 0x02u
#define HID_MOD_ALTGR 0x40u

typedef struct {
    uint8_t usage;
    uint8_t mod;
} hid_key_t;

/*
 * Indexed by ASCII value. Entries left out default to {0, 0}, which reads as
 * not typeable. Letters follow QWERTZ, so y and z use each other's physical
 * key. Codes are USB HID Keyboard page (0x07) usage IDs.
 */
static const hid_key_t HID_KEYMAP_DE[128] = {
    [' ']  = {0x2C, 0},

    ['a'] = {0x04, 0}, ['b'] = {0x05, 0}, ['c'] = {0x06, 0}, ['d'] = {0x07, 0},
    ['e'] = {0x08, 0}, ['f'] = {0x09, 0}, ['g'] = {0x0A, 0}, ['h'] = {0x0B, 0},
    ['i'] = {0x0C, 0}, ['j'] = {0x0D, 0}, ['k'] = {0x0E, 0}, ['l'] = {0x0F, 0},
    ['m'] = {0x10, 0}, ['n'] = {0x11, 0}, ['o'] = {0x12, 0}, ['p'] = {0x13, 0},
    ['q'] = {0x14, 0}, ['r'] = {0x15, 0}, ['s'] = {0x16, 0}, ['t'] = {0x17, 0},
    ['u'] = {0x18, 0}, ['v'] = {0x19, 0}, ['w'] = {0x1A, 0}, ['x'] = {0x1B, 0},
    ['y'] = {0x1D, 0}, ['z'] = {0x1C, 0},

    ['A'] = {0x04, HID_MOD_SHIFT}, ['B'] = {0x05, HID_MOD_SHIFT},
    ['C'] = {0x06, HID_MOD_SHIFT}, ['D'] = {0x07, HID_MOD_SHIFT},
    ['E'] = {0x08, HID_MOD_SHIFT}, ['F'] = {0x09, HID_MOD_SHIFT},
    ['G'] = {0x0A, HID_MOD_SHIFT}, ['H'] = {0x0B, HID_MOD_SHIFT},
    ['I'] = {0x0C, HID_MOD_SHIFT}, ['J'] = {0x0D, HID_MOD_SHIFT},
    ['K'] = {0x0E, HID_MOD_SHIFT}, ['L'] = {0x0F, HID_MOD_SHIFT},
    ['M'] = {0x10, HID_MOD_SHIFT}, ['N'] = {0x11, HID_MOD_SHIFT},
    ['O'] = {0x12, HID_MOD_SHIFT}, ['P'] = {0x13, HID_MOD_SHIFT},
    ['Q'] = {0x14, HID_MOD_SHIFT}, ['R'] = {0x15, HID_MOD_SHIFT},
    ['S'] = {0x16, HID_MOD_SHIFT}, ['T'] = {0x17, HID_MOD_SHIFT},
    ['U'] = {0x18, HID_MOD_SHIFT}, ['V'] = {0x19, HID_MOD_SHIFT},
    ['W'] = {0x1A, HID_MOD_SHIFT}, ['X'] = {0x1B, HID_MOD_SHIFT},
    ['Y'] = {0x1D, HID_MOD_SHIFT}, ['Z'] = {0x1C, HID_MOD_SHIFT},

    ['1'] = {0x1E, 0}, ['2'] = {0x1F, 0}, ['3'] = {0x20, 0}, ['4'] = {0x21, 0},
    ['5'] = {0x22, 0}, ['6'] = {0x23, 0}, ['7'] = {0x24, 0}, ['8'] = {0x25, 0},
    ['9'] = {0x26, 0}, ['0'] = {0x27, 0},

    ['!'] = {0x1E, HID_MOD_SHIFT}, ['"'] = {0x1F, HID_MOD_SHIFT},
    ['$'] = {0x21, HID_MOD_SHIFT}, ['%'] = {0x22, HID_MOD_SHIFT},
    ['&'] = {0x23, HID_MOD_SHIFT}, ['/'] = {0x24, HID_MOD_SHIFT},
    ['('] = {0x25, HID_MOD_SHIFT}, [')'] = {0x26, HID_MOD_SHIFT},
    ['='] = {0x27, HID_MOD_SHIFT},

    [','] = {0x36, 0}, [';'] = {0x36, HID_MOD_SHIFT},
    ['.'] = {0x37, 0}, [':'] = {0x37, HID_MOD_SHIFT},
    ['-'] = {0x38, 0}, ['_'] = {0x38, HID_MOD_SHIFT},
    ['?'] = {0x2D, HID_MOD_SHIFT},
    ['+'] = {0x30, 0}, ['*'] = {0x30, HID_MOD_SHIFT}, ['~'] = {0x30, HID_MOD_ALTGR},
    ['#'] = {0x31, 0}, ['\''] = {0x31, HID_MOD_SHIFT},
    ['<'] = {0x64, 0}, ['>'] = {0x64, HID_MOD_SHIFT}, ['|'] = {0x64, HID_MOD_ALTGR},

    ['@'] = {0x14, HID_MOD_ALTGR},
    ['{'] = {0x24, HID_MOD_ALTGR}, ['['] = {0x25, HID_MOD_ALTGR},
    [']'] = {0x26, HID_MOD_ALTGR}, ['}'] = {0x27, HID_MOD_ALTGR},
    ['\\'] = {0x2D, HID_MOD_ALTGR},
};

/* Fills usage and mod for c, or returns false if it cannot be typed. */
static inline bool hid_key_for(char c, uint8_t *usage, uint8_t *mod)
{
    unsigned char u = (unsigned char) c;

    if (u >= 128)
        return false;
    if (HID_KEYMAP_DE[u].usage == 0)
        return false;

    *usage = HID_KEYMAP_DE[u].usage;
    *mod   = HID_KEYMAP_DE[u].mod;
    return true;
}

#endif
