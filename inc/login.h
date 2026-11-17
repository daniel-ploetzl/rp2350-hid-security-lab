/*
 * Stored input sequence state machine
 *
 *   At each re-activation the device types the stored input sequence, waits
 *   for the host session, then types the final configured action before
 *   simulated activity starts. It is a non-blocking state machine driven
 *   from the main loop, one key event per pass, so it never stalls tud_task().
 *
 *   Every key down is followed by its release, so nothing is held and the host
 *   sees each character exactly once with no auto-repeat.
 */

#ifndef LOGIN_H
#define LOGIN_H

#include <stdbool.h>
#include <stdint.h>
#include "flash_config.h"

/* Authenticates and decrypts the stored record into short-lived SRAM, then
 * starts the sequence. Invalid or absent records mean nothing is typed. */
void login_begin(void);

/* Accepts a record directly so the sequence can be tested without reading
 * from the fixed flash address. */
void login_begin_from(const login_creds_t *lc);

/* Advances the sequence. Call every main-loop pass with the monotonic time. */
void login_task(uint32_t now_ms);

/* True while the stored sequence owns the keyboard. */
bool login_in_progress(void);

/* True once the sequence and the wait have finished. */
bool login_is_done(void);

#endif
