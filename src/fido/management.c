/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "pico_keys.h"
#include "fido.h"
#include "apdu.h"
#include "version.h"
#include "files.h"
#include "management.h"
#include "management_usb.h"
#include "mbedtls/constant_time.h"

bool is_gpg = true;

int man_process_apdu();
int man_unload();

const uint8_t man_aid[] = {
    8,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
};
static const uint8_t yubikey_man_aid[] = {
    7,
    0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01
};
extern void scan_all();
extern void init_otp();
int man_select(app_t *a, uint8_t force) {
    a->process_apdu = man_process_apdu;
    a->unload = man_unload;
    sprintf((char *) res_APDU, "%d.%d.0", PICO_FIDO_DEVICE_VERSION_MAJOR, PICO_FIDO_DEVICE_VERSION_MINOR);
    res_APDU_size = (uint16_t)strlen((char *) res_APDU);
    apdu.ne = res_APDU_size;
    if (force) {
        scan_all();
#ifdef ENABLE_OTP_APP
        init_otp();
#endif
    }
    is_gpg = false;
    return PICOKEY_OK;
}

INITIALIZER ( man_ctor ) {
    register_app(man_select, man_aid);
    register_app(man_select, yubikey_man_aid);
}

int man_unload() {
    return PICOKEY_OK;
}

static const uint8_t _openpgp_aid[] = {
    6,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
};
static const uint8_t _piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x08,
};
static const uint8_t _hsmauth_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01,
};

typedef struct {
    bool usb_enabled_set;
    uint16_t usb_enabled;
    bool auto_eject_timeout_set;
    uint16_t auto_eject_timeout;
    bool chalresp_timeout_set;
    uint8_t chalresp_timeout;
    bool device_flags_set;
    uint8_t device_flags;
    bool config_lock_set;
    uint8_t config_lock[MAN_CONFIG_LOCK_LEN];
} man_config_t;

static int man_tlv_next(const uint8_t *buf, uint16_t len, uint16_t *offset,
                        uint8_t *tag, uint8_t *tag_len, const uint8_t **data) {
    if (*offset == len) {
        return 0;
    }
    if (*offset > len || (uint16_t)(len - *offset) < 2) {
        return -1;
    }
    uint16_t p = *offset;
    uint8_t t = buf[p++];
    uint8_t l = buf[p++];
    if ((l & 0x80) != 0 || (uint16_t)(len - p) < l) {
        return -1;
    }
    *tag = t;
    *tag_len = l;
    *data = buf + p;
    *offset = (uint16_t)(p + l);
    return 1;
}

static bool all_zero(const uint8_t *data, uint16_t len) {
    uint8_t v = 0;
    for (uint16_t i = 0; i < len; ++i) {
        v |= data[i];
    }
    return v == 0;
}

static int man_load_config(man_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    file_t *ef = search_dynamic_file(EF_DEV_CONF);
    if (!file_has_data(ef)) {
        return 0;
    }

    const uint8_t *buf = file_get_data(ef);
    uint16_t len = file_get_size(ef);
    uint16_t offset = 0;
    while (offset < len) {
        uint8_t tag = 0, tag_len = 0;
        const uint8_t *data = NULL;
        int r = man_tlv_next(buf, len, &offset, &tag, &tag_len, &data);
        if (r <= 0) {
            return -1;
        }
        switch (tag) {
            case TAG_USB_ENABLED:
                if (tag_len != 1 && tag_len != 2) return -1;
                cfg->usb_enabled_set = true;
                cfg->usb_enabled = tag_len == 2 ? get_uint16_t_be(data) : data[0];
                break;
            case TAG_AUTO_EJECT_TIMEOUT:
                if (tag_len != 2) return -1;
                cfg->auto_eject_timeout_set = true;
                cfg->auto_eject_timeout = get_uint16_t_be(data);
                break;
            case TAG_CHALRESP_TIMEOUT:
                if (tag_len != 1) return -1;
                cfg->chalresp_timeout_set = true;
                cfg->chalresp_timeout = data[0];
                break;
            case TAG_DEVICE_FLAGS:
                if (tag_len != 1) return -1;
                cfg->device_flags_set = true;
                cfg->device_flags = data[0];
                break;
            case TAG_CONFIG_LOCK:
                if (tag_len != MAN_CONFIG_LOCK_LEN) return -1;
                if (!all_zero(data, tag_len)) {
                    cfg->config_lock_set = true;
                    memcpy(cfg->config_lock, data, MAN_CONFIG_LOCK_LEN);
                }
                break;
            case TAG_UNLOCK:
                if (tag_len != MAN_CONFIG_LOCK_LEN) return -1;
                break;
            case TAG_REBOOT:
                if (tag_len != 0) return -1;
                break;
            default:
                return -1;
        }
    }
    return 0;
}

static uint16_t man_append_tlv(uint8_t *out, uint16_t offset, uint8_t tag,
                               const uint8_t *data, uint8_t len) {
    out[offset++] = tag;
    out[offset++] = len;
    if (len) {
        memcpy(out + offset, data, len);
        offset = (uint16_t)(offset + len);
    }
    return offset;
}

static int man_store_config(const man_config_t *cfg) {
    uint8_t out[40];
    uint16_t offset = 0;
    uint8_t tmp[2];

    if (cfg->usb_enabled_set) {
        put_uint16_t_be(cfg->usb_enabled, tmp);
        offset = man_append_tlv(out, offset, TAG_USB_ENABLED, tmp, 2);
    }
    if (cfg->auto_eject_timeout_set) {
        put_uint16_t_be(cfg->auto_eject_timeout, tmp);
        offset = man_append_tlv(out, offset, TAG_AUTO_EJECT_TIMEOUT, tmp, 2);
    }
    if (cfg->chalresp_timeout_set) {
        offset = man_append_tlv(out, offset, TAG_CHALRESP_TIMEOUT,
                                &cfg->chalresp_timeout, 1);
    }
    if (cfg->device_flags_set) {
        offset = man_append_tlv(out, offset, TAG_DEVICE_FLAGS,
                                &cfg->device_flags, 1);
    }
    if (cfg->config_lock_set) {
        offset = man_append_tlv(out, offset, TAG_CONFIG_LOCK,
                                cfg->config_lock, MAN_CONFIG_LOCK_LEN);
    }

    file_t *ef = file_new(EF_DEV_CONF);
    int r = file_put_data(ef, out, offset);
    if (r != PICOKEY_OK) {
        return r;
    }
    low_flash_available();
    return PICOKEY_OK;
}

static uint16_t man_supported_caps(void) {
    uint16_t caps = CAP_FIDO2 | CAP_OTP | CAP_U2F | CAP_OATH | CAP_MANAGEMENT;
    if (app_exists(_openpgp_aid + 1, _openpgp_aid[0])) {
        caps |= CAP_OPENPGP;
    }
    if (app_exists(_piv_aid + 1, _piv_aid[0])) {
        caps |= CAP_PIV;
    }
    if (app_exists(_hsmauth_aid + 1, _hsmauth_aid[0])) {
        caps |= CAP_HSMAUTH;
    }
    return caps;
}

int man_get_usb_config(uint16_t *enabled, bool *configured) {
    man_config_t cfg;
    if (enabled == NULL || configured == NULL || man_load_config(&cfg) != 0) {
        return -1;
    }
    *configured = cfg.usb_enabled_set;
    *enabled = cfg.usb_enabled_set ? cfg.usb_enabled : man_supported_caps();
    return 0;
}

int man_get_capability_state(uint16_t *supported, uint16_t *enabled,
                             bool *configured, bool *locked) {
    man_config_t cfg;
    if (supported == NULL || enabled == NULL || configured == NULL || locked == NULL ||
        man_load_config(&cfg) != 0) {
        return -1;
    }
    *supported = man_supported_caps();
    *configured = cfg.usb_enabled_set;
    *enabled = cfg.usb_enabled_set ? cfg.usb_enabled : *supported;
    *locked = cfg.config_lock_set;
    return 0;
}

int man_get_enabled_caps(uint16_t *enabled) {
    bool configured = false;
    return man_get_usb_config(enabled, &configured);
}

bool cap_supported(uint16_t cap) {
    uint16_t enabled = 0;
    return man_get_enabled_caps(&enabled) == 0 && (enabled & cap) != 0;
}

int man_get_config() {
    man_config_t cfg;
    if (man_load_config(&cfg) != 0) {
        return -1;
    }
    uint16_t supported = man_supported_caps();
    uint16_t enabled = 0;
    if (man_get_enabled_caps(&enabled) != 0) {
        return -1;
    }
    uint8_t tmp[2];

    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 0;

    put_uint16_t_be(supported, tmp);
    res_APDU_size = man_append_tlv(res_APDU, res_APDU_size, TAG_USB_SUPPORTED, tmp, 2);
    res_APDU[res_APDU_size++] = TAG_SERIAL;
    res_APDU[res_APDU_size++] = 4;
    memcpy(res_APDU + res_APDU_size, pico_serial.id, 4);
    res_APDU[res_APDU_size] &= ~0xFC;
    res_APDU_size += 4;
    res_APDU[res_APDU_size++] = TAG_FORM_FACTOR;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x01;
    res_APDU[res_APDU_size++] = TAG_VERSION;
    res_APDU[res_APDU_size++] = 3;
    res_APDU[res_APDU_size++] = PICO_FIDO_DEVICE_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PICO_FIDO_DEVICE_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0;

    put_uint16_t_be(enabled, tmp);
    res_APDU_size = man_append_tlv(res_APDU, res_APDU_size, TAG_USB_ENABLED, tmp, 2);
    if (cfg.auto_eject_timeout_set) {
        put_uint16_t_be(cfg.auto_eject_timeout, tmp);
        res_APDU_size = man_append_tlv(res_APDU, res_APDU_size,
                                       TAG_AUTO_EJECT_TIMEOUT, tmp, 2);
    }
    if (cfg.chalresp_timeout_set) {
        res_APDU_size = man_append_tlv(res_APDU, res_APDU_size,
                                       TAG_CHALRESP_TIMEOUT,
                                       &cfg.chalresp_timeout, 1);
    }
    uint8_t flags = cfg.device_flags_set ? cfg.device_flags : FLAG_EJECT;
    res_APDU_size = man_append_tlv(res_APDU, res_APDU_size,
                                   TAG_DEVICE_FLAGS, &flags, 1);
    uint8_t locked = cfg.config_lock_set ? 1 : 0;
    res_APDU_size = man_append_tlv(res_APDU, res_APDU_size,
                                   TAG_CONFIG_LOCK, &locked, 1);

    res_APDU[0] = (uint8_t)(res_APDU_size - 1);
    return 0;
}

int cmd_read_config() {
    if (man_get_config() != 0) {
        return SW_WRONG_DATA();
    }
    return SW_OK();
}

static uint16_t man_write_config_impl(const uint8_t *request, uint16_t request_len,
                                      bool maintenance_authorized) {
    if (request_len < 1 || request[0] != request_len - 1) {
        return MAN_SW_WRONG_DATA;
    }

    man_config_t cfg;
    if (man_load_config(&cfg) != 0) {
        return MAN_SW_WRONG_DATA;
    }
    man_config_t next = cfg;
    bool unlock_seen = false;
    bool unlock_valid = false;
    bool changed = false;
    uint16_t offset = 0;
    const uint8_t *buf = request + 1;
    uint16_t len = (uint16_t)(request_len - 1);

    while (offset < len) {
        uint8_t tag = 0, tag_len = 0;
        const uint8_t *data = NULL;
        int r = man_tlv_next(buf, len, &offset, &tag, &tag_len, &data);
        if (r <= 0) {
            return MAN_SW_WRONG_DATA;
        }
        switch (tag) {
            case TAG_UNLOCK:
                if (tag_len != MAN_CONFIG_LOCK_LEN) return MAN_SW_WRONG_DATA;
                unlock_seen = true;
                unlock_valid = cfg.config_lock_set &&
                    mbedtls_ct_memcmp(cfg.config_lock, data, MAN_CONFIG_LOCK_LEN) == 0;
                break;
            case TAG_USB_ENABLED: {
                if (tag_len != 2) return MAN_SW_WRONG_DATA;
                uint16_t enabled = get_uint16_t_be(data);
                if ((enabled & ~man_supported_caps()) != 0 || enabled == 0) {
                    return MAN_SW_WRONG_DATA;
                }
                const uint16_t management_transports =
                    CAP_OTP | CAP_U2F | CAP_FIDO2 | CAP_MANAGEMENT;
                if ((enabled & management_transports) == 0) {
                    return MAN_SW_WRONG_DATA;
                }
                next.usb_enabled_set = true;
                next.usb_enabled = enabled;
                changed = true;
                break;
            }
            case TAG_AUTO_EJECT_TIMEOUT:
                if (tag_len != 2) return MAN_SW_WRONG_DATA;
                next.auto_eject_timeout_set = true;
                next.auto_eject_timeout = get_uint16_t_be(data);
                changed = true;
                break;
            case TAG_CHALRESP_TIMEOUT:
                if (tag_len != 1) return MAN_SW_WRONG_DATA;
                next.chalresp_timeout_set = true;
                next.chalresp_timeout = data[0];
                changed = true;
                break;
            case TAG_DEVICE_FLAGS:
                if (tag_len != 1) return MAN_SW_WRONG_DATA;
                next.device_flags_set = true;
                next.device_flags = data[0];
                changed = true;
                break;
            case TAG_CONFIG_LOCK:
                if (tag_len != MAN_CONFIG_LOCK_LEN) return MAN_SW_WRONG_DATA;
                if (all_zero(data, tag_len)) {
                    next.config_lock_set = false;
                    memset(next.config_lock, 0, sizeof(next.config_lock));
                }
                else {
                    next.config_lock_set = true;
                    memcpy(next.config_lock, data, MAN_CONFIG_LOCK_LEN);
                }
                changed = true;
                break;
            case TAG_REBOOT:
                if (tag_len != 0) return MAN_SW_WRONG_DATA;
                break;
            default:
                return MAN_SW_WRONG_DATA;
        }
    }

    if (!maintenance_authorized) {
        if (cfg.config_lock_set && (!unlock_seen || !unlock_valid)) {
            return MAN_SW_SECURITY_STATUS_NOT_SATISFIED;
        }
        if (!cfg.config_lock_set && unlock_seen) {
            return MAN_SW_SECURITY_STATUS_NOT_SATISFIED;
        }
    }

    if (changed) {
        int r = man_store_config(&next);
        if (r != PICOKEY_OK) {
            return MAN_SW_WRONG_DATA;
        }
    }
    return MAN_SW_OK;
}

uint16_t man_write_config(const uint8_t *request, uint16_t request_len) {
    return man_write_config_impl(request, request_len, false);
}

uint16_t man_write_config_maintenance(const uint8_t *request, uint16_t request_len) {
    return man_write_config_impl(request, request_len, true);
}

extern int cbor_reset();
int cmd_factory_reset() {
    cbor_reset();
    return SW_OK();
}

int cmd_write_config() {
    uint16_t sw = man_write_config(apdu.data, (uint16_t)apdu.nc);
    return set_res_sw((uint8_t)(sw >> 8), (uint8_t)sw);
}

#define INS_READ_CONFIG             0x1D
#define INS_WRITE_CONFIG            0x1C
#define INS_RESET                   0x1E    // Reset device

static const cmd_t cmds[] = {
    { INS_READ_CONFIG, cmd_read_config },
    { INS_WRITE_CONFIG, cmd_write_config },
    { INS_RESET, cmd_factory_reset },
    { 0x00, 0x0 }
};

int man_process_apdu() {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
