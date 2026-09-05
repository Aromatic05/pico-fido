#ifndef _MANAGEMENT_USB_H_
#define _MANAGEMENT_USB_H_

#include <stdint.h>

#include "management.h"
#include "phy.h"

static inline uint8_t man_usb_interfaces_for_caps(uint16_t caps) {
    uint8_t interfaces = 0;

    if (caps & CAP_OTP) {
        interfaces |= PHY_USB_ITF_KB;
    }
    if (caps & (CAP_U2F | CAP_FIDO2)) {
        interfaces |= PHY_USB_ITF_HID;
    }
    if (caps & (CAP_MANAGEMENT | CAP_OATH | CAP_PIV | CAP_OPENPGP | CAP_HSMAUTH)) {
        interfaces |= PHY_USB_ITF_CCID | PHY_USB_ITF_WCID;
    }
    return interfaces;
}

#endif // _MANAGEMENT_USB_H_
