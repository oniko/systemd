/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "luks2-fido2.h"

#include "json.h"
#include "memory-util.h"
#include "hexdecoct.h"

int acquire_luks2_key(
                struct crypt_device *cd,
                const char *json,
                const char *device,
                char **pins,
                char **ret_keyslot_passphrase,
                size_t *ret_keyslot_passphrase_size) {

        int r;
        Fido2EnrollFlags required;
        size_t cid_size, salt_size, decrypted_key_size;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        _cleanup_free_ void *cid = NULL, *salt = NULL;
        _cleanup_free_ char *rp_id = NULL;
        _cleanup_(erase_and_freep) void *decrypted_key = NULL;
        _cleanup_(erase_and_freep) char *base64_encoded = NULL;

        r = parse_luks2_fido2_data(json, &rp_id, &salt, &salt_size, &cid, &cid_size, &required);
        if (r < 0)
                return r;

        /* configured to use pin but none was passed */
        if ((required & FIDO2ENROLL_PIN) && !pins)
                return -ENOANO;

        r = fido2_use_hmac_hash(
                        device,
                        rp_id ?: "io.systemd.cryptsetup",
                        salt, salt_size,
                        cid, cid_size,
                        pins,
                        required,
                        &decrypted_key,
                        &decrypted_key_size);
        if (r == -ENOLCK) /* libcryptsetup returns -EPERM on wrong pass/pin */
                r = -EPERM;
        if (r < 0)
                /* log */
                return r;

        /* Before using this key as passphrase we base64 encode it, for compat with homed */
        r = base64mem(decrypted_key, decrypted_key_size, &base64_encoded);
        if (r < 0)
                return -ENOMEM;

        *ret_keyslot_passphrase = TAKE_PTR(base64_encoded);
        *ret_keyslot_passphrase_size = strlen(*ret_keyslot_passphrase);

        return 0;
}

/* this function expects valid "systemd-fido2" in json */
int parse_luks2_fido2_data(
                const char *json,
                char **ret_rp_id,
                void **ret_salt,
                size_t *ret_salt_size,
                void **ret_cid,
                size_t *ret_cid_size,
                Fido2EnrollFlags *ret_required) {

        _cleanup_free_ void *cid = NULL, *salt = NULL;
        size_t cid_size = 0, salt_size = 0;
        _cleanup_free_ char *rp = NULL;
        int r;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        JsonVariant *w;
        /* For backward compatibility, require pin and presence by default */
        Fido2EnrollFlags required = FIDO2ENROLL_PIN | FIDO2ENROLL_UP;

        assert(json);

        r = json_parse(json, 0, &v, NULL, NULL);
        if (r < 0)
                return -EINVAL;

        w = json_variant_by_key(v, "fido2-credential");
        if (!w)
                return -EINVAL;

        r = unbase64mem(json_variant_string(w), SIZE_MAX, &cid, &cid_size);
        if (r < 0)
                return r;

        w = json_variant_by_key(v, "fido2-salt");
        if (!w)
                return -EINVAL;

        r = unbase64mem(json_variant_string(w), SIZE_MAX, &salt, &salt_size);
        if (r < 0)
                return r;

        w = json_variant_by_key(v, "fido2-rp");
        if (w) {
                /* The "rp" field is optional. */
                rp = strdup(json_variant_string(w));
                if (!rp)
                        return log_oom();
        }

        w = json_variant_by_key(v, "fido2-clientPin-required");
        if (w)
                /* The "fido2-clientPin-required" field is optional. */
                SET_FLAG(required, FIDO2ENROLL_PIN, json_variant_boolean(w));

        w = json_variant_by_key(v, "fido2-up-required");
        if (w)
                /* The "fido2-up-required" field is optional. */
                SET_FLAG(required, FIDO2ENROLL_UP, json_variant_boolean(w));

        w = json_variant_by_key(v, "fido2-uv-required");
        if (w)
                /* The "fido2-uv-required" field is optional. */
                SET_FLAG(required, FIDO2ENROLL_UV, json_variant_boolean(w));

        *ret_rp_id = TAKE_PTR(rp);
        *ret_cid = TAKE_PTR(cid);
        *ret_cid_size = cid_size;
        *ret_salt = TAKE_PTR(salt);
        *ret_salt_size = salt_size;
        *ret_required = required;

        return 0;
}
