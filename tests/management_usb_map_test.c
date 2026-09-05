#include "management_usb.h"

#include <assert.h>

static void expect(uint16_t caps, uint8_t interfaces) {
    assert(man_usb_interfaces_for_caps(caps) == interfaces);
}

int main(void) {
    expect(CAP_OTP, PHY_USB_ITF_KB);
    expect(CAP_U2F, PHY_USB_ITF_HID);
    expect(CAP_FIDO2, PHY_USB_ITF_HID);
    expect(CAP_OATH, PHY_USB_ITF_CCID | PHY_USB_ITF_WCID);
    expect(CAP_PIV, PHY_USB_ITF_CCID | PHY_USB_ITF_WCID);
    expect(CAP_OPENPGP, PHY_USB_ITF_CCID | PHY_USB_ITF_WCID);
    expect(CAP_MANAGEMENT, PHY_USB_ITF_CCID | PHY_USB_ITF_WCID);
    expect(CAP_HSMAUTH, PHY_USB_ITF_CCID | PHY_USB_ITF_WCID);
    expect(CAP_OTP | CAP_U2F | CAP_FIDO2,
           PHY_USB_ITF_KB | PHY_USB_ITF_HID);
    expect(CAP_OTP | CAP_U2F | CAP_FIDO2 | CAP_OATH | CAP_PIV |
               CAP_OPENPGP | CAP_MANAGEMENT,
           PHY_USB_ITF_CCID | PHY_USB_ITF_WCID |
               PHY_USB_ITF_HID | PHY_USB_ITF_KB);
    return 0;
}
