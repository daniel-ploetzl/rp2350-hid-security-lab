/*
 * Public interface for HID input behaviour engine.
 */

#ifndef INPUT_TASKS_H
#define INPUT_TASKS_H

#include <stdint.h>
#include <stdbool.h>
#include "flash_config.h"

void input_tasks_init(void);
void input_tasks_run(bool active);
void input_tasks_stop(void);

/* Authenticates and decrypts the stored record into short-lived SRAM, then
 * starts the sequence. Invalid or absent records mean nothing is typed. */
void input_sequence_begin(void);

/* Accepts a record directly so the sequence can be tested without reading
 * from the fixed flash address. */
void input_sequence_begin_from(const input_sequence_config_t *sequence);

/* Advances the sequence. Call every main-loop pass with the monotonic time. */
void input_sequence_task(uint32_t now_ms);

/* True while the stored sequence owns the keyboard. */
bool input_sequence_in_progress(void);

/* True once the sequence and the wait have finished. */
bool input_sequence_is_done(void);

#endif
