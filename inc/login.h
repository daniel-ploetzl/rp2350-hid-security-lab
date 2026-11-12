/*
 * Login typist
 *
 *   At each re-activation the device types the stored username, Return, the
 *   password, Return, then waits so the host can finish logging in before the
 *   simulated activity starts. It is a non-blocking state machine driven from
 *   the main loop, one key event per pass, so it never stalls tud_task().
 *
 *   Every key down is followed by its release, so nothing is held and the host
 *   sees each character exactly once with no auto-repeat.
 */

#ifndef LOGIN_H
#define LOGIN_H

#include <stdbool.h>
#include <stdint.h>

#include "flash_config.h"

/* Starts the sequence from the stored record. No valid record means nothing to
 * type, so it completes at once. Called at the re-activation edge. */
void login_begin(void);

/* The half that takes the record, so the sequence can be driven on the host
 * against a crafted login without a fixed flash address. login_begin() calls
 * it with login_read(). */
void login_begin_from(const login_creds_t *lc);

/* Advances the sequence. Call every main-loop pass with the monotonic time. */
void login_task(uint32_t now_ms);

/* True while typing or waiting, when the login owns the keyboard. */
bool login_in_progress(void);

/* True once the sequence and the wait have finished. */
bool login_is_done(void);

#endif
