/*
 * YubiHSM Auth compatibility applet.
 *
 * Implements the AES-128/SCP03 credential path used by yubikit HsmAuthSession.
 * Credential state uses the normal Pico Keys dynamic-file layer so successful
 * APDUs keep the same power-loss durability semantics as the other applets.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "apdu.h"
#include "file.h"
#include "management.h"
#include "pico_keys.h"
#include "random.h"
#include "version.h"

#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

#define HSMAUTH_TAG_LABEL                 0x71
#define HSMAUTH_TAG_LABEL_LIST            0x72
#define HSMAUTH_TAG_CREDENTIAL_PASSWORD   0x73
#define HSMAUTH_TAG_ALGORITHM             0x74
#define HSMAUTH_TAG_KEY_ENC               0x75
#define HSMAUTH_TAG_KEY_MAC               0x76
#define HSMAUTH_TAG_CONTEXT               0x77
#define HSMAUTH_TAG_RESPONSE              0x78
#define HSMAUTH_TAG_VERSION               0x79
#define HSMAUTH_TAG_TOUCH                 0x7A
#define HSMAUTH_TAG_MANAGEMENT_KEY        0x7B
#define HSMAUTH_TAG_PUBLIC_KEY            0x7C
#define HSMAUTH_TAG_PRIVATE_KEY           0x7D

#define HSMAUTH_INS_PUT                   0x01
#define HSMAUTH_INS_DELETE                0x02
#define HSMAUTH_INS_CALCULATE             0x03
#define HSMAUTH_INS_GET_CHALLENGE         0x04
#define HSMAUTH_INS_LIST                  0x05
#define HSMAUTH_INS_RESET                 0x06
#define HSMAUTH_INS_GET_VERSION           0x07
#define HSMAUTH_INS_PUT_MANAGEMENT_KEY    0x08
#define HSMAUTH_INS_GET_MGMT_RETRIES      0x09
#define HSMAUTH_INS_GET_PUBLIC_KEY        0x0A
#define HSMAUTH_INS_CHANGE_PASSWORD       0x0B

#define HSMAUTH_ALG_AES128                0x26
#define HSMAUTH_KEY_LEN                   16
#define HSMAUTH_PASSWORD_LEN              16
#define HSMAUTH_MAX_LABEL_LEN             64
#define HSMAUTH_INITIAL_RETRIES            8

#define HSMAUTH_CONFIG_FID                0xBC00
#define HSMAUTH_CREDENTIAL_FID_BASE       0xBC01
#define HSMAUTH_MAX_CREDENTIALS           24

#define HSMAUTH_CONFIG_MAGIC              0x484D5343u
#define HSMAUTH_CREDENTIAL_MAGIC          0x484D5341u
#define HSMAUTH_STORAGE_VERSION           1

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t version;
    uint8_t management_retries;
    uint8_t reserved[2];
    uint8_t management_key[HSMAUTH_KEY_LEN];
} hsmauth_config_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t version;
    uint8_t algorithm;
    uint8_t touch_required;
    uint8_t retries;
    uint8_t label_len;
    uint8_t reserved[3];
    uint8_t label[HSMAUTH_MAX_LABEL_LEN];
    uint8_t credential_password[HSMAUTH_PASSWORD_LEN];
    uint8_t key_enc[HSMAUTH_KEY_LEN];
    uint8_t key_mac[HSMAUTH_KEY_LEN];
} hsmauth_credential_t;

typedef struct {
    uint8_t tag;
    uint8_t len;
    const uint8_t *data;
} hsmauth_tlv_t;

const uint8_t hsmauth_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01,
};

static uint16_t retry_sw(uint8_t retries) {
    return (uint16_t)(0x63C0u | (retries & 0x0Fu));
}

static uint16_t set_sw(uint16_t sw) {
    return set_res_sw((uint8_t)(sw >> 8), (uint8_t)sw);
}

static bool valid_config(const hsmauth_config_t *cfg) {
    return cfg != NULL && cfg->magic == HSMAUTH_CONFIG_MAGIC &&
           cfg->version == HSMAUTH_STORAGE_VERSION &&
           cfg->management_retries <= HSMAUTH_INITIAL_RETRIES;
}

static bool valid_credential(const hsmauth_credential_t *cred) {
    return cred != NULL && cred->magic == HSMAUTH_CREDENTIAL_MAGIC &&
           cred->version == HSMAUTH_STORAGE_VERSION &&
           cred->algorithm == HSMAUTH_ALG_AES128 &&
           cred->touch_required <= 1 &&
           cred->retries <= HSMAUTH_INITIAL_RETRIES &&
           cred->label_len >= 1 && cred->label_len <= HSMAUTH_MAX_LABEL_LEN;
}

static int load_config(hsmauth_config_t *cfg) {
    if (cfg == NULL) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->magic = HSMAUTH_CONFIG_MAGIC;
    cfg->version = HSMAUTH_STORAGE_VERSION;
    cfg->management_retries = HSMAUTH_INITIAL_RETRIES;

    file_t *ef = search_dynamic_file(HSMAUTH_CONFIG_FID);
    if (!file_has_data(ef)) {
        return PICOKEY_OK;
    }
    if (file_get_size(ef) != sizeof(*cfg)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    memcpy(cfg, file_get_data(ef), sizeof(*cfg));
    return valid_config(cfg) ? PICOKEY_OK : PICOKEY_ERR_FILE_NOT_FOUND;
}

static int store_config(const hsmauth_config_t *cfg) {
    if (!valid_config(cfg)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    file_t *ef = file_new(HSMAUTH_CONFIG_FID);
    if (ef == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    int ret = file_put_data(ef, (const uint8_t *)cfg, sizeof(*cfg));
    if (ret == PICOKEY_OK) {
        low_flash_available();
    }
    return ret;
}

static file_t *credential_file(unsigned slot) {
    if (slot >= HSMAUTH_MAX_CREDENTIALS) {
        return NULL;
    }
    return search_dynamic_file((uint16_t)(HSMAUTH_CREDENTIAL_FID_BASE + slot));
}

static bool load_credential(unsigned slot, hsmauth_credential_t *cred) {
    file_t *ef = credential_file(slot);
    if (!file_has_data(ef) || file_get_size(ef) != sizeof(*cred)) {
        return false;
    }
    memcpy(cred, file_get_data(ef), sizeof(*cred));
    return valid_credential(cred);
}

static int store_credential(unsigned slot, const hsmauth_credential_t *cred) {
    if (slot >= HSMAUTH_MAX_CREDENTIALS || !valid_credential(cred)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    file_t *ef = file_new((uint16_t)(HSMAUTH_CREDENTIAL_FID_BASE + slot));
    if (ef == NULL) {
        return PICOKEY_ERR_NO_MEMORY;
    }
    int ret = file_put_data(ef, (const uint8_t *)cred, sizeof(*cred));
    if (ret == PICOKEY_OK) {
        low_flash_available();
    }
    return ret;
}

static int find_credential(const uint8_t *label, uint8_t label_len,
                           hsmauth_credential_t *cred, unsigned *slot) {
    for (unsigned i = 0; i < HSMAUTH_MAX_CREDENTIALS; ++i) {
        hsmauth_credential_t candidate;
        if (!load_credential(i, &candidate)) {
            continue;
        }
        if (candidate.label_len == label_len &&
            mbedtls_ct_memcmp(candidate.label, label, label_len) == 0) {
            if (cred != NULL) {
                *cred = candidate;
            }
            if (slot != NULL) {
                *slot = i;
            }
            mbedtls_platform_zeroize(&candidate, sizeof(candidate));
            return PICOKEY_OK;
        }
        mbedtls_platform_zeroize(&candidate, sizeof(candidate));
    }
    return PICOKEY_ERR_FILE_NOT_FOUND;
}

static int find_free_slot(unsigned *slot) {
    if (slot == NULL) {
        return PICOKEY_ERR_NULL_PARAM;
    }
    for (unsigned i = 0; i < HSMAUTH_MAX_CREDENTIALS; ++i) {
        hsmauth_credential_t cred;
        if (!load_credential(i, &cred)) {
            *slot = i;
            return PICOKEY_OK;
        }
        mbedtls_platform_zeroize(&cred, sizeof(cred));
    }
    return PICOKEY_ERR_NO_MEMORY;
}

static int tlv_next(const uint8_t *buf, uint16_t len, uint16_t *offset,
                    hsmauth_tlv_t *tlv) {
    if (buf == NULL || offset == NULL || tlv == NULL || *offset >= len) {
        return 0;
    }
    if ((uint16_t)(len - *offset) < 2) {
        return -1;
    }
    uint16_t p = *offset;
    tlv->tag = buf[p++];
    tlv->len = buf[p++];
    if ((tlv->len & 0x80u) != 0 || (uint16_t)(len - p) < tlv->len) {
        return -1;
    }
    tlv->data = buf + p;
    *offset = (uint16_t)(p + tlv->len);
    return 1;
}

static uint16_t append_tlv(uint8_t *out, uint16_t offset, uint8_t tag,
                           const uint8_t *data, uint8_t len) {
    out[offset++] = tag;
    out[offset++] = len;
    if (len != 0) {
        memcpy(out + offset, data, len);
        offset = (uint16_t)(offset + len);
    }
    return offset;
}

static uint16_t verify_management_key(const uint8_t key[HSMAUTH_KEY_LEN],
                                      hsmauth_config_t *cfg) {
    if (load_config(cfg) != PICOKEY_OK) {
        return MAN_SW_WRONG_DATA;
    }
    if (cfg->management_retries == 0) {
        return retry_sw(0);
    }
    if (mbedtls_ct_memcmp(cfg->management_key, key, HSMAUTH_KEY_LEN) != 0) {
        cfg->management_retries--;
        if (store_config(cfg) != PICOKEY_OK) {
            return MAN_SW_WRONG_DATA;
        }
        return retry_sw(cfg->management_retries);
    }
    if (cfg->management_retries != HSMAUTH_INITIAL_RETRIES) {
        cfg->management_retries = HSMAUTH_INITIAL_RETRIES;
        if (store_config(cfg) != PICOKEY_OK) {
            return MAN_SW_WRONG_DATA;
        }
    }
    return MAN_SW_OK;
}

static uint16_t verify_credential_password(hsmauth_credential_t *cred,
                                           unsigned slot,
                                           const uint8_t password[HSMAUTH_PASSWORD_LEN]) {
    if (cred->retries == 0) {
        return retry_sw(0);
    }
    if (mbedtls_ct_memcmp(cred->credential_password, password,
                          HSMAUTH_PASSWORD_LEN) != 0) {
        cred->retries--;
        if (store_credential(slot, cred) != PICOKEY_OK) {
            return MAN_SW_WRONG_DATA;
        }
        return retry_sw(cred->retries);
    }
    if (cred->retries != HSMAUTH_INITIAL_RETRIES) {
        cred->retries = HSMAUTH_INITIAL_RETRIES;
        if (store_credential(slot, cred) != PICOKEY_OK) {
            return MAN_SW_WRONG_DATA;
        }
    }
    return MAN_SW_OK;
}

static int scp03_derive(const uint8_t key[HSMAUTH_KEY_LEN], uint8_t type,
                        uint16_t bits, const uint8_t *context, size_t context_len,
                        uint8_t out[HSMAUTH_KEY_LEN]) {
    uint8_t input[48] = {0};
    if (context_len > sizeof(input) - 16 || (bits != 0x0080 && bits != 0x0040)) {
        return -1;
    }
    input[11] = type;
    input[12] = 0;
    input[13] = (uint8_t)(bits >> 8);
    input[14] = (uint8_t)bits;
    input[15] = 1;
    memcpy(input + 16, context, context_len);

    const mbedtls_cipher_info_t *cipher =
        mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (cipher == NULL) {
        return -1;
    }
    uint8_t mac[16];
    int ret = mbedtls_cipher_cmac(cipher, key, 128, input,
                                  16 + context_len, mac);
    if (ret == 0) {
        memcpy(out, mac, bits / 8);
    }
    mbedtls_platform_zeroize(mac, sizeof(mac));
    mbedtls_platform_zeroize(input, sizeof(input));
    return ret;
}

static bool touch_timed_out(void) {
#ifdef ENABLE_EMULATION
    return false;
#else
    return wait_button();
#endif
}

int hsmauth_process_apdu(void);

static int hsmauth_select(app_t *app, uint8_t force) {
    (void)force;
    if (!cap_supported(CAP_HSMAUTH)) {
        return PICOKEY_ERR_FILE_NOT_FOUND;
    }
    app->process_apdu = hsmauth_process_apdu;
    app->unload = NULL;

    const uint8_t version[3] = {
        PICO_FIDO_DEVICE_VERSION_MAJOR,
        PICO_FIDO_DEVICE_VERSION_MINOR,
        0,
    };
    res_APDU_size = append_tlv(res_APDU, 0, HSMAUTH_TAG_VERSION,
                               version, sizeof(version));
    apdu.ne = res_APDU_size;
    return PICOKEY_OK;
}

INITIALIZER ( hsmauth_ctor ) {
    register_app(hsmauth_select, hsmauth_aid);
}

static int cmd_put(void) {
    const uint8_t *management_key = NULL;
    const uint8_t *label = NULL;
    const uint8_t *password = NULL;
    const uint8_t *key_enc = NULL;
    const uint8_t *key_mac = NULL;
    uint8_t label_len = 0;
    uint8_t algorithm = 0;
    uint8_t touch = 0;
    bool have_algorithm = false;
    bool have_touch = false;

    uint16_t offset = 0;
    hsmauth_tlv_t tlv;
    while (offset < apdu.nc) {
        if (tlv_next(apdu.data, (uint16_t)apdu.nc, &offset, &tlv) <= 0) {
            return SW_WRONG_DATA();
        }
        switch (tlv.tag) {
        case HSMAUTH_TAG_MANAGEMENT_KEY:
            if (management_key != NULL || tlv.len != HSMAUTH_KEY_LEN) return SW_WRONG_DATA();
            management_key = tlv.data;
            break;
        case HSMAUTH_TAG_LABEL:
            if (label != NULL || tlv.len < 1 || tlv.len > HSMAUTH_MAX_LABEL_LEN) return SW_WRONG_DATA();
            label = tlv.data;
            label_len = tlv.len;
            break;
        case HSMAUTH_TAG_ALGORITHM:
            if (have_algorithm || tlv.len != 1) return SW_WRONG_DATA();
            algorithm = tlv.data[0];
            have_algorithm = true;
            break;
        case HSMAUTH_TAG_KEY_ENC:
            if (key_enc != NULL || tlv.len != HSMAUTH_KEY_LEN) return SW_WRONG_DATA();
            key_enc = tlv.data;
            break;
        case HSMAUTH_TAG_KEY_MAC:
            if (key_mac != NULL || tlv.len != HSMAUTH_KEY_LEN) return SW_WRONG_DATA();
            key_mac = tlv.data;
            break;
        case HSMAUTH_TAG_CREDENTIAL_PASSWORD:
            if (password != NULL || tlv.len != HSMAUTH_PASSWORD_LEN) return SW_WRONG_DATA();
            password = tlv.data;
            break;
        case HSMAUTH_TAG_TOUCH:
            if (have_touch || tlv.len != 1 || tlv.data[0] > 1) return SW_WRONG_DATA();
            touch = tlv.data[0];
            have_touch = true;
            break;
        default:
            return SW_WRONG_DATA();
        }
    }

    if (management_key == NULL || label == NULL || password == NULL ||
        !have_algorithm || !have_touch || algorithm != HSMAUTH_ALG_AES128 ||
        key_enc == NULL || key_mac == NULL) {
        return SW_WRONG_DATA();
    }

    hsmauth_config_t cfg;
    uint16_t sw = verify_management_key(management_key, &cfg);
    mbedtls_platform_zeroize(&cfg, sizeof(cfg));
    if (sw != MAN_SW_OK) {
        return set_sw(sw);
    }
    if (find_credential(label, label_len, NULL, NULL) == PICOKEY_OK) {
        return SW_WRONG_DATA();
    }

    unsigned slot = 0;
    if (find_free_slot(&slot) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }

    hsmauth_credential_t cred = {0};
    cred.magic = HSMAUTH_CREDENTIAL_MAGIC;
    cred.version = HSMAUTH_STORAGE_VERSION;
    cred.algorithm = algorithm;
    cred.touch_required = touch;
    cred.retries = HSMAUTH_INITIAL_RETRIES;
    cred.label_len = label_len;
    memcpy(cred.label, label, label_len);
    memcpy(cred.credential_password, password, HSMAUTH_PASSWORD_LEN);
    memcpy(cred.key_enc, key_enc, HSMAUTH_KEY_LEN);
    memcpy(cred.key_mac, key_mac, HSMAUTH_KEY_LEN);
    int ret = store_credential(slot, &cred);
    mbedtls_platform_zeroize(&cred, sizeof(cred));
    return ret == PICOKEY_OK ? SW_OK() : SW_EXEC_ERROR();
}

static int parse_management_and_label(const uint8_t **management_key,
                                      const uint8_t **label, uint8_t *label_len) {
    uint16_t offset = 0;
    hsmauth_tlv_t tlv;
    *management_key = NULL;
    *label = NULL;
    *label_len = 0;
    while (offset < apdu.nc) {
        if (tlv_next(apdu.data, (uint16_t)apdu.nc, &offset, &tlv) <= 0) {
            return -1;
        }
        if (tlv.tag == HSMAUTH_TAG_MANAGEMENT_KEY && *management_key == NULL &&
            tlv.len == HSMAUTH_KEY_LEN) {
            *management_key = tlv.data;
        }
        else if (tlv.tag == HSMAUTH_TAG_LABEL && *label == NULL &&
                 tlv.len >= 1 && tlv.len <= HSMAUTH_MAX_LABEL_LEN) {
            *label = tlv.data;
            *label_len = tlv.len;
        }
        else {
            return -1;
        }
    }
    return *management_key != NULL && *label != NULL ? 0 : -1;
}

static int cmd_delete(void) {
    const uint8_t *management_key;
    const uint8_t *label;
    uint8_t label_len;
    if (parse_management_and_label(&management_key, &label, &label_len) != 0) {
        return SW_WRONG_DATA();
    }
    hsmauth_config_t cfg;
    uint16_t sw = verify_management_key(management_key, &cfg);
    mbedtls_platform_zeroize(&cfg, sizeof(cfg));
    if (sw != MAN_SW_OK) {
        return set_sw(sw);
    }

    unsigned slot = 0;
    if (find_credential(label, label_len, NULL, &slot) != PICOKEY_OK) {
        return SW_FILE_NOT_FOUND();
    }
    return delete_file(credential_file(slot)) == PICOKEY_OK ? SW_OK() : SW_EXEC_ERROR();
}

static int cmd_list(void) {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    res_APDU_size = 0;
    for (unsigned i = 0; i < HSMAUTH_MAX_CREDENTIALS; ++i) {
        hsmauth_credential_t cred;
        if (!load_credential(i, &cred)) {
            continue;
        }
        uint8_t item[HSMAUTH_MAX_LABEL_LEN + 3] = {0};
        item[0] = cred.algorithm;
        item[1] = cred.touch_required;
        memcpy(item + 2, cred.label, cred.label_len);
        item[2 + cred.label_len] = cred.retries;
        res_APDU_size = append_tlv(res_APDU, res_APDU_size,
                                   HSMAUTH_TAG_LABEL_LIST, item,
                                   (uint8_t)(cred.label_len + 3));
        mbedtls_platform_zeroize(item, sizeof(item));
        mbedtls_platform_zeroize(&cred, sizeof(cred));
    }
    apdu.ne = res_APDU_size;
    return SW_OK();
}

static int parse_label_only(const uint8_t **label, uint8_t *label_len) {
    uint16_t offset = 0;
    hsmauth_tlv_t tlv;
    *label = NULL;
    *label_len = 0;
    while (offset < apdu.nc) {
        if (tlv_next(apdu.data, (uint16_t)apdu.nc, &offset, &tlv) <= 0 ||
            tlv.tag != HSMAUTH_TAG_LABEL || *label != NULL ||
            tlv.len < 1 || tlv.len > HSMAUTH_MAX_LABEL_LEN) {
            return -1;
        }
        *label = tlv.data;
        *label_len = tlv.len;
    }
    return *label != NULL ? 0 : -1;
}

static int cmd_get_challenge(void) {
    const uint8_t *label;
    uint8_t label_len;
    if (parse_label_only(&label, &label_len) != 0) {
        return SW_WRONG_DATA();
    }
    hsmauth_credential_t cred;
    if (find_credential(label, label_len, &cred, NULL) != PICOKEY_OK) {
        return SW_FILE_NOT_FOUND();
    }
    mbedtls_platform_zeroize(&cred, sizeof(cred));
    random_gen(NULL, res_APDU, 8);
    res_APDU_size = 8;
    apdu.ne = 8;
    return SW_OK();
}

static int cmd_calculate(void) {
    const uint8_t *label = NULL;
    const uint8_t *context = NULL;
    const uint8_t *password = NULL;
    const uint8_t *card_crypto = NULL;
    uint8_t label_len = 0;
    uint16_t offset = 0;
    hsmauth_tlv_t tlv;

    while (offset < apdu.nc) {
        if (tlv_next(apdu.data, (uint16_t)apdu.nc, &offset, &tlv) <= 0) {
            return SW_WRONG_DATA();
        }
        switch (tlv.tag) {
        case HSMAUTH_TAG_LABEL:
            if (label != NULL || tlv.len < 1 || tlv.len > HSMAUTH_MAX_LABEL_LEN) return SW_WRONG_DATA();
            label = tlv.data;
            label_len = tlv.len;
            break;
        case HSMAUTH_TAG_CONTEXT:
            if (context != NULL || tlv.len != 16) return SW_WRONG_DATA();
            context = tlv.data;
            break;
        case HSMAUTH_TAG_CREDENTIAL_PASSWORD:
            if (password != NULL || tlv.len != HSMAUTH_PASSWORD_LEN) return SW_WRONG_DATA();
            password = tlv.data;
            break;
        case HSMAUTH_TAG_RESPONSE:
            if (card_crypto != NULL || tlv.len != 8) return SW_WRONG_DATA();
            card_crypto = tlv.data;
            break;
        default:
            return SW_WRONG_DATA();
        }
    }
    if (label == NULL || context == NULL || password == NULL) {
        return SW_WRONG_DATA();
    }

    hsmauth_credential_t cred;
    unsigned slot = 0;
    if (find_credential(label, label_len, &cred, &slot) != PICOKEY_OK) {
        return SW_FILE_NOT_FOUND();
    }
    uint16_t sw = verify_credential_password(&cred, slot, password);
    if (sw != MAN_SW_OK) {
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        return set_sw(sw);
    }
    if (cred.touch_required && touch_timed_out()) {
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    uint8_t s_enc[16] = {0};
    uint8_t s_mac[16] = {0};
    uint8_t s_rmac[16] = {0};
    if (scp03_derive(cred.key_enc, 0x04, 0x0080, context, 16, s_enc) != 0 ||
        scp03_derive(cred.key_mac, 0x06, 0x0080, context, 16, s_mac) != 0 ||
        scp03_derive(cred.key_mac, 0x07, 0x0080, context, 16, s_rmac) != 0) {
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        mbedtls_platform_zeroize(s_enc, sizeof(s_enc));
        mbedtls_platform_zeroize(s_mac, sizeof(s_mac));
        mbedtls_platform_zeroize(s_rmac, sizeof(s_rmac));
        return SW_EXEC_ERROR();
    }

    if (card_crypto != NULL) {
        uint8_t expected[16] = {0};
        if (scp03_derive(s_mac, 0x00, 0x0040, context, 16, expected) != 0 ||
            mbedtls_ct_memcmp(expected, card_crypto, 8) != 0) {
            mbedtls_platform_zeroize(expected, sizeof(expected));
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            mbedtls_platform_zeroize(s_enc, sizeof(s_enc));
            mbedtls_platform_zeroize(s_mac, sizeof(s_mac));
            mbedtls_platform_zeroize(s_rmac, sizeof(s_rmac));
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        mbedtls_platform_zeroize(expected, sizeof(expected));
    }

    memcpy(res_APDU, s_enc, 16);
    memcpy(res_APDU + 16, s_mac, 16);
    memcpy(res_APDU + 32, s_rmac, 16);
    res_APDU_size = 48;
    apdu.ne = 48;

    mbedtls_platform_zeroize(&cred, sizeof(cred));
    mbedtls_platform_zeroize(s_enc, sizeof(s_enc));
    mbedtls_platform_zeroize(s_mac, sizeof(s_mac));
    mbedtls_platform_zeroize(s_rmac, sizeof(s_rmac));
    return SW_OK();
}

static int cmd_reset(void) {
    if (P1(apdu) != 0xDE || P2(apdu) != 0xAD || apdu.nc != 0) {
        return SW_INCORRECT_P1P2();
    }
    file_t *cfg = search_dynamic_file(HSMAUTH_CONFIG_FID);
    if (cfg != NULL && delete_file(cfg) != PICOKEY_OK) {
        return SW_EXEC_ERROR();
    }
    for (unsigned i = 0; i < HSMAUTH_MAX_CREDENTIALS; ++i) {
        file_t *ef = credential_file(i);
        if (ef != NULL && delete_file(ef) != PICOKEY_OK) {
            return SW_EXEC_ERROR();
        }
    }
    return SW_OK();
}

static int cmd_get_version(void) {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    res_APDU[0] = PICO_FIDO_DEVICE_VERSION_MAJOR;
    res_APDU[1] = PICO_FIDO_DEVICE_VERSION_MINOR;
    res_APDU[2] = 0;
    res_APDU_size = 3;
    apdu.ne = 3;
    return SW_OK();
}

static int cmd_put_management_key(void) {
    const uint8_t *old_key = NULL;
    const uint8_t *new_key = NULL;
    uint16_t offset = 0;
    hsmauth_tlv_t tlv;
    while (offset < apdu.nc) {
        if (tlv_next(apdu.data, (uint16_t)apdu.nc, &offset, &tlv) <= 0 ||
            tlv.tag != HSMAUTH_TAG_MANAGEMENT_KEY || tlv.len != HSMAUTH_KEY_LEN) {
            return SW_WRONG_DATA();
        }
        if (old_key == NULL) {
            old_key = tlv.data;
        }
        else if (new_key == NULL) {
            new_key = tlv.data;
        }
        else {
            return SW_WRONG_DATA();
        }
    }
    if (old_key == NULL || new_key == NULL) {
        return SW_WRONG_DATA();
    }

    hsmauth_config_t cfg;
    uint16_t sw = verify_management_key(old_key, &cfg);
    if (sw != MAN_SW_OK) {
        mbedtls_platform_zeroize(&cfg, sizeof(cfg));
        return set_sw(sw);
    }
    memcpy(cfg.management_key, new_key, HSMAUTH_KEY_LEN);
    cfg.management_retries = HSMAUTH_INITIAL_RETRIES;
    int ret = store_config(&cfg);
    mbedtls_platform_zeroize(&cfg, sizeof(cfg));
    return ret == PICOKEY_OK ? SW_OK() : SW_EXEC_ERROR();
}

static int cmd_get_management_retries(void) {
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    hsmauth_config_t cfg;
    if (load_config(&cfg) != PICOKEY_OK) {
        return SW_WRONG_DATA();
    }
    res_APDU[0] = cfg.management_retries;
    res_APDU_size = 1;
    apdu.ne = 1;
    mbedtls_platform_zeroize(&cfg, sizeof(cfg));
    return SW_OK();
}

static int cmd_not_supported(void) {
    return SW_INS_NOT_SUPPORTED();
}

static const cmd_t hsmauth_cmds[] = {
    { HSMAUTH_INS_PUT, cmd_put },
    { HSMAUTH_INS_DELETE, cmd_delete },
    { HSMAUTH_INS_CALCULATE, cmd_calculate },
    { HSMAUTH_INS_GET_CHALLENGE, cmd_get_challenge },
    { HSMAUTH_INS_LIST, cmd_list },
    { HSMAUTH_INS_RESET, cmd_reset },
    { HSMAUTH_INS_GET_VERSION, cmd_get_version },
    { HSMAUTH_INS_PUT_MANAGEMENT_KEY, cmd_put_management_key },
    { HSMAUTH_INS_GET_MGMT_RETRIES, cmd_get_management_retries },
    { HSMAUTH_INS_GET_PUBLIC_KEY, cmd_not_supported },
    { HSMAUTH_INS_CHANGE_PASSWORD, cmd_not_supported },
    { 0x00, NULL },
};

int hsmauth_process_apdu(void) {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    if (!cap_supported(CAP_HSMAUTH)) {
        return SW_FILE_NOT_FOUND();
    }
    for (const cmd_t *cmd = hsmauth_cmds; cmd->ins != 0x00; ++cmd) {
        if (cmd->ins == INS(apdu)) {
            return cmd->cmd_handler();
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
