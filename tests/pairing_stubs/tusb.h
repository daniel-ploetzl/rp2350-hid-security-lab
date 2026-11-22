#ifndef TEST_TUSB_H
#define TEST_TUSB_H

#include <stdbool.h>
#include <stdint.h>
#define SCSI_SENSE_ILLEGAL_REQUEST 5u
void tud_msc_set_sense(uint8_t lun, uint8_t key, uint8_t code, uint8_t qualifier);

bool tud_mounted(void);

#endif
