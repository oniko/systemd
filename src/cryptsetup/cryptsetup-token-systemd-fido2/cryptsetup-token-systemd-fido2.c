/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <libcryptsetup.h>

#include "cryptsetup-token.h"
#include "hexdecoct.h"
#include "memory-util.h"
#include "strv.h"
#include "luks2-fido2.h"
#include "json.h"

#define TOKEN_NAME "systemd-fido2"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

#define crypt_log_dbg(cd, x...) crypt_logf(cd, CRYPT_LOG_DEBUG, x)
#define crypt_log_err(cd, x...) crypt_logf(cd, CRYPT_LOG_ERROR, x)
#define crypt_log_std(cd, x...) crypt_logf(cd, CRYPT_LOG_NORMAL, x)

/* for libcryptsetup debug purpose */
_public_ const char *cryptsetup_token_version(void) {
        return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR;
}

/*
static int log_debug_open_error(struct crypt_device *cd, int r) {
        if (r == -EAGAIN)
                crypt_log_dbg(cd, "TPM2 device not found.");
        else if (r == -ENXIO)
                crypt_log_dbg(cd, "No matching TPM2 token data found.");
        else if (r == -ENOMEM)
                crypt_log_dbg(cd, "Not Enough memory.");
        else if (r == -EINVAL)
                crypt_log_dbg(cd, "Internal error unlocking device using system-tmp2 token.");

        return r;
}
*/

_public_ int cryptsetup_token_open_pin(
                struct crypt_device *cd, /* is always LUKS2 context */
                int token /* is always >= 0 */,
                const char *pin,
                size_t pin_size,
                char **password, /* freed by cryptsetup_token_buffer_free */
                size_t *password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        int r;
        const char *json;
        _cleanup_strv_free_erase_ char **pins = NULL;

        assert(token >= 0);

        /* This must not fail at this moment (internal error) */
        r = crypt_token_json_get(cd, token, &json);
        assert(token == r);
        assert(json);

        /* systemd fido2 code uses pin lists internally, libcryptsetup does not */
        if (pin) {
                pins = strv_new(pin);
                if (!pins)
                        return -ENOMEM;
        }

        return acquire_luks2_key(cd, json, (const char *)usrptr, pins, password, password_len);
}

/*
 * This function is called from within following libcryptsetup calls
 * provided conditions further below are met:
 *
 * crypt_activate_by_token(), crypt_activate_by_token_type(type == 'systemd-tpm2'):
 *
 * - token is assigned to at least one luks2 keyslot eligible to activate LUKS2 device
 *   (alternatively: name is set to null, flags contains CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY
 *    and token is assigned to at least single keyslot).
 *
 * - if plugin defines validate funtion (see cryptsetup_token_validate below) it must have
 *   passed the check (aka return 0)
 */
_public_ int cryptsetup_token_open(
                struct crypt_device *cd, /* is always LUKS2 context */
                int token /* is always >= 0 */,
                char **password, /* freed by cryptsetup_token_buffer_free */
                size_t *password_len,
                void *usrptr /* plugin defined parameter passed to crypt_activate_by_token*() API */) {

        return cryptsetup_token_open_pin(cd, token, NULL, 0, password, password_len, usrptr);
}


/*
 * libcryptsetup callback for memory deallocation of 'password' parameter passed in
 * any crypt_token_open_* plugin function
 */
_public_ void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len) {
        erase_and_free(buffer);
}

/*
 * prints systemd-tpm2 token content in crypt_dump().
 * 'type' and 'keyslots' fields are printed by libcryptsetup
 */
_public_ void cryptsetup_token_dump(
                struct crypt_device *cd /* is always LUKS2 context */,
                const char *json /* validated 'systemd-tpm2' token if cryptsetup_token_validate is defined */) {

}

/*
 * Note:
 *   If plugin is available in library path, it's called in before following libcryptsetup calls:
 *
 *   crypt_token_json_set, crypt_dump, any crypt_activate_by_token_* flavour
 */
_public_ int cryptsetup_token_validate(
                struct crypt_device *cd, /* is always LUKS2 context */
                const char *json /* contains valid 'type' and 'keyslots' fields. 'type' is 'systemd-tpm2' */) {

        int r;
        JsonVariant *w;
        size_t dummy_size;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ void *dummy = NULL;

        r = json_parse(json, 0, &v, NULL, NULL);
        if (r < 0) {
                crypt_log_dbg(cd, "Could not parse " TOKEN_NAME " json object%s.",
                              r == -ENOMEM ? " (not enough memory)" : "");
                return 1;
        }

        w = json_variant_by_key(v, "fido2-credential");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_dbg(cd, "FIDO2 token data lacks 'fido2-credential' field.");
                return 1;
        }

        r = unbase64mem(json_variant_string(w), SIZE_MAX, &dummy, &dummy_size);
        if (r < 0) {
                crypt_log_dbg(cd, "Invalid base64 data in 'fido2-credential' field.");
                return 1;
        }

        w = json_variant_by_key(v, "fido2-salt");
        if (!w || !json_variant_is_string(w)) {
                crypt_log_dbg(cd, "FIDO2 token data lacks 'fido2-salt' field.");
                return 1;
        }

        dummy = mfree(dummy);
        r = unbase64mem(json_variant_string(w), SIZE_MAX, &dummy, &dummy_size);
        if (r < 0) {
                crypt_log_dbg(cd, "Failed to decode base64 encoded salt.");
                return 1;
        }

        /* The "rp" field is optional. */
        w = json_variant_by_key(v, "fido2-rp");
        if (w && !json_variant_is_string(w)) {
                crypt_log_dbg(cd, "FIDO2 token data's 'fido2-rp' field is not a string.");
                return 1;
        }

        /* The "fido2-clientPin-required" field is optional. */
        w = json_variant_by_key(v, "fido2-clientPin-required");
        if (w && !json_variant_is_boolean(w)) {
                crypt_log_dbg(cd, "FIDO2 token data's 'fido2-clientPin-required' field is not a boolean.");
                return 1;
        }

        /* The "fido2-up-required" field is optional. */
        w = json_variant_by_key(v, "fido2-up-required");
        if (w && !json_variant_is_boolean(w)) {
                crypt_log_dbg(cd, "FIDO2 token data's 'fido2-up-required' field is not a boolean.");
                return 1;
        }

        /* The "fido2-uv-required" field is optional. */
        w = json_variant_by_key(v, "fido2-uv-required");
        if (w && !json_variant_is_boolean(w)) {
                crypt_log_dbg(cd, "FIDO2 token data's 'fido2-uv-required' field is not a boolean.");
                return 1;
        }

        return 0;
}
