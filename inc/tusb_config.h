#ifndef TUSB_CONFIG_H
#define TUSB_CONFIG_H

#define CFG_TUSB_RHPORT0_MODE   OPT_MODE_DEVICE

#define CFG_TUD_ENDPOINT0_SIZE  64

#define CFG_TUD_HID             1
#define CFG_TUD_HID_EP_BUFSIZE  64

#define CFG_TUD_CDC             0
/* MSC carries the rootless challenge exchange through the host automount. */
#define CFG_TUD_MSC             1
#define CFG_TUD_MSC_EP_BUFSIZE  512
#define CFG_TUD_MIDI            0
#define CFG_TUD_VENDOR          0

#endif
