/* packet-mbus-security.c
 *
 * Copyright 2026, Martin B. Petersen <mbp@flonidan.dk>
 * Copyright 2026, Kenneth Soerensen <ks@flonidan.dk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/proto_data.h>
#include <wsutil/wsgcrypt.h>
#include "packet-mbus-security.h"

#define MBUS_SEC_CONST_KEYSIZE              16
#define MBUS_SEC_PC_KEY                     0 /* PC key, copied from zbee but don't think it is needed */

/* Values in the key rings. */
typedef struct {
    int frame_num;
    char* label;
    uint8_t key[MBUS_SEC_CONST_KEYSIZE];
} mbus_key_record_t;

/* Field pointers. */
static int hf_mbus_sec_key;
static int hf_mbus_sec_decryption_key;
static int hf_mbus_sec_encrypted_length;
static int hf_mbus_sec_unencrypted_length;
static int hf_mbus_sec_message_counter;

/* Subtree pointers. */
static int ett_mbus_sec;

static expert_field ei_mbus_sec_encrypted_payload;
static expert_field ei_mbus_sec_encrypted_payload_sliced;
static expert_field ei_mbus_sec_extended_source_unknown;

static uat_t       *mbus_sec_key_table_uat;

static const value_string byte_order_vals[] = {
    { 0, "Normal"},
    { 1, "Reverse"},
    { 0, NULL }
};

/* UAT Key Entry */
typedef struct {
    char* string;
    uint8_t byte_order;
    char* label;
} uat_mbus_key_record_t;

UAT_CSTRING_CB_DEF(uat_key_records, string, uat_mbus_key_record_t)
UAT_VS_DEF(uat_key_records, byte_order, uat_mbus_key_record_t, uint8_t, 0, "Normal")
UAT_CSTRING_CB_DEF(uat_key_records, label, uat_mbus_key_record_t)

static GSList* mbus_secure_ctx_list = NULL;
static GSList* mbus_pc_keyring = NULL;
static uat_mbus_key_record_t* uat_key_records = NULL;
static int num_uat_key_records = 0;

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      mbus_security_parse_key
 *  DESCRIPTION
 *      Parses a key string from left to right into a buffer with
 *      increasing (normal byte order) or decreasing (reverse byte
 *      order) address.
 *  PARAMETERS
 *      const char    *key_str - pointer to the string
 *      uint8_t         *key_buf - destination buffer in memory
 *      bool           big_end - fill key_buf with incrementing address
 *  RETURNS
 *      bool
 *---------------------------------------------------------------
 */
static bool
mbus_security_parse_key(const char *key_str, uint8_t *key_buf, bool byte_order)
{
    int j;
    char temp;
    bool string_mode = false;

    /* Clear the key. */
    memset(key_buf, 0, MBUS_SEC_CONST_KEYSIZE);
    if (key_str == NULL) {
        return false;
    }

    /*
     * Attempt to parse the key string. The key string must
     * be at least 16 pairs of hexidecimal digits with the
     * following optional separators: ':', '-', " ", or 16
     * alphanumeric characters after a double-quote.
     */
    if ( (temp = *key_str++) == '"') {
        string_mode = true;
        temp = *key_str++;
    }

    j = byte_order ? MBUS_SEC_CONST_KEYSIZE - 1 : 0;
    for (int i = MBUS_SEC_CONST_KEYSIZE - 1; i >= 0; i--) {
        if ( string_mode ) {
            if ( g_ascii_isprint(temp) ) {
                key_buf[j] = temp;
                temp = *key_str++;
            } else {
                return false;
            }
        }
        else {
            /* If this character is a separator, skip it. */
            if ( (temp == ':') || (temp == '-') || (temp == ' ') ) temp = *(key_str++);

            /* Process a nibble. */
            if ( g_ascii_isxdigit (temp) ) key_buf[j] = g_ascii_xdigit_value(temp)<<4;
            else return false;

            /* Get the next nibble. */
            temp = *(key_str++);

            /* Process another nibble. */
            if ( g_ascii_isxdigit (temp) ) key_buf[j] |= g_ascii_xdigit_value(temp);
            else return false;

            /* Get the next nibble. */
            temp = *(key_str++);
        }

        /* Move key_buf pointer */
        if ( byte_order ) {
            j--;
        } else {
            j++;
        }

    } /* for */

    /* If we get this far, then the key was good. */
    return true;
} /* mbus_security_parse_key */

static void* uat_key_record_copy_cb(void* n, const void* o, size_t siz _U_)
{
    uat_mbus_key_record_t* new_key = (uat_mbus_key_record_t *)n;
    const uat_mbus_key_record_t* old_key = (const uat_mbus_key_record_t *)o;

    new_key->string = g_strdup(old_key->string);
    new_key->label = g_strdup(old_key->label);
    new_key->byte_order = old_key->byte_order;

    return new_key;
}

static bool uat_key_record_update_cb(void* r, char** err)
{
    uat_mbus_key_record_t* rec = (uat_mbus_key_record_t *)r;
    uint8_t key[MBUS_SEC_CONST_KEYSIZE];

    if (rec->string == NULL) {
        *err = g_strdup("Key can't be blank");
        return false;
    } else {
        g_strstrip(rec->string);

        if (rec->string[0] != 0) {
            *err = NULL;
            if ( !mbus_security_parse_key(rec->string, key, rec->byte_order) ) {
                *err = g_strdup_printf("Expecting %d hexadecimal bytes or\n"
                        "a %d character double-quoted string", MBUS_SEC_CONST_KEYSIZE, MBUS_SEC_CONST_KEYSIZE);
                return false;
            }
        } else {
            *err = g_strdup("Key can't be blank");
            return false;
        }
    }
    return true;
}

static void uat_key_record_free_cb(void*r)
{
    uat_mbus_key_record_t* key = (uat_mbus_key_record_t *)r;

    g_free(key->string);
    g_free(key->label);
}

static void mbus_free_key_record(gpointer ptr)
{
    mbus_key_record_t *k = (mbus_key_record_t *)ptr;

    g_free(k->label);
    g_free(k);
}

static void uat_key_record_post_update(void)
{
    int i;
    mbus_key_record_t key_record;
    uint8_t key[MBUS_SEC_CONST_KEYSIZE];

    /* empty the key ring */
    if (mbus_pc_keyring) {
       g_slist_free_full(mbus_pc_keyring, mbus_free_key_record);
       mbus_pc_keyring = NULL;
    }

    /* Load the pre-configured slist from the UAT. */
    for (i=0; (uat_key_records) && (i<num_uat_key_records) ; i++) {
        if (mbus_security_parse_key(uat_key_records[i].string, key, uat_key_records[i].byte_order)) {
            key_record.frame_num = MBUS_SEC_PC_KEY;
            key_record.label = g_strdup(uat_key_records[i].label);
            memcpy(key_record.key, key, MBUS_SEC_CONST_KEYSIZE);
            mbus_pc_keyring = g_slist_prepend(mbus_pc_keyring, g_memdup2(&key_record, sizeof(mbus_key_record_t)));
        }
    }
}

static int mbus_secure_ctx_compare(gconstpointer a, gconstpointer b)
{
    const mbus_secure_ctx_t* a_ctx = (mbus_secure_ctx_t*)a;
    const mbus_secure_ctx_t* b_ctx = (mbus_secure_ctx_t*)b;
    if ((a_ctx->identification_number == b_ctx->identification_number) &&
        (a_ctx->manufacturer == b_ctx->manufacturer) &&
        (a_ctx->version == b_ctx->version) &&
        (a_ctx->device == b_ctx->device)) {
        return 0;
    }
    return -1;
}

static void mbus_add_secure_ctx_if_not_exist(const mbus_secure_ctx_t* secure_ctx)
{
    GSList* item = g_slist_find_custom(mbus_secure_ctx_list, secure_ctx, mbus_secure_ctx_compare);
    if (item == NULL) {
        mbus_secure_ctx_list = g_slist_prepend(mbus_secure_ctx_list, g_memdup2(secure_ctx, sizeof(mbus_secure_ctx_t)));
    }
}

static void mbus_free_secure_ctx(gpointer ptr)
{
    g_free(ptr);
}

static void proto_cleanup_mbus_secure(void)
{
    if (mbus_secure_ctx_list) {
       g_slist_free_full(mbus_secure_ctx_list, mbus_free_secure_ctx);
       mbus_secure_ctx_list = NULL;
    }
}

void mbus_security_register(module_t *mbus_prefs, int proto)
{
    static hf_register_info hf[] = {
        { &hf_mbus_sec_key,
          { "Key", "mbus.sec.key", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_mbus_sec_decryption_key,
          { "Key Label", "mbus.sec.decryption_key", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_mbus_sec_encrypted_length,
          { "Encrypted Length", "mbus.sec.encrypted_length", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_mbus_sec_unencrypted_length,
          { "Unencrypted Length", "mbus.sec.unencrypted_length", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_mbus_sec_message_counter,
          { "Message Counter", "mbus.sec.message_counter", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_mbus_sec
    };

    static ei_register_info ei[] = {
        { &ei_mbus_sec_encrypted_payload, { "mbus_sec.encrypted_payload", PI_UNDECODED, PI_WARN, "Encrypted Payload", EXPFILL }},
        { &ei_mbus_sec_encrypted_payload_sliced, { "mbus_sec.encrypted_payload_sliced", PI_UNDECODED, PI_WARN, "Encrypted payload, cut short when capturing - can't decrypt", EXPFILL }},
        { &ei_mbus_sec_extended_source_unknown, { "mbus_sec.extended_source_unknown", PI_PROTOCOL, PI_NOTE, "Extended Source: Unknown", EXPFILL }},
    };

    expert_module_t* expert_mbus_sec;

    static uat_field_t key_uat_fields[] = {
        UAT_FLD_CSTRING(uat_key_records, string, "Key",
                        "A 16-byte key in hexadecimal with optional dash-,\n"
                        "colon-, or space-separator characters, or a\n"
                        "a 16-character string in double-quotes."),
        UAT_FLD_VS(uat_key_records, byte_order, "Byte Order", byte_order_vals,
                        "Byte order of key."),
        UAT_FLD_CSTRING(uat_key_records, label, "Label", "User label for key."),
        UAT_END_FIELDS
    };

    /* If no prefs module was supplied, register our own. */
    if (mbus_prefs == NULL) {
        mbus_prefs = prefs_register_protocol(proto, NULL);
    }

    mbus_sec_key_table_uat = uat_new("Pre-configured Keys",
                               sizeof(uat_mbus_key_record_t),
                               "mbus_pc_keys",
                               true,
                               &uat_key_records,
                               &num_uat_key_records,
                               UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                               NULL,  /* TODO: ptr to help manual? */
                               uat_key_record_copy_cb,
                               uat_key_record_update_cb,
                               uat_key_record_free_cb,
                               uat_key_record_post_update,
                               NULL,
                               key_uat_fields);

    prefs_register_uat_preference(mbus_prefs,
                                  "key_table",
                                  "Pre-configured Keys",
                                  "Pre-configured link or network keys.",
                                  mbus_sec_key_table_uat);

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mbus_sec = expert_register_protocol(proto);
    expert_register_field_array(expert_mbus_sec, ei, array_length(ei));

    /* Register de-init routine */
    register_cleanup_routine(proto_cleanup_mbus_secure);
} /* mbus_security_register */

static bool
mbus_sec_gcm128_decrypt_payload(const uint8_t *enc_buffer, int enc_len,
                                const uint8_t *iv, int iv_len,
                                const uint8_t *aad, int aad_len,
                                const uint8_t *tag, int tag_len,
                                uint8_t *dec_buffer, mbus_key_record_t *key_record)
{
    gcry_cipher_hd_t handle;
    if (gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0)) {
        return false;
    }
    if (gcry_cipher_setkey(handle, key_record->key, MBUS_SEC_CONST_KEYSIZE)) {
        goto err_out;
    }
    if (gcry_cipher_setiv(handle, iv, iv_len)) {
        goto err_out;
    }
    if (gcry_cipher_authenticate(handle, aad, aad_len)) {
        goto err_out;
    }
    if (gcry_cipher_decrypt(handle, dec_buffer, enc_len,
                            enc_buffer, enc_len)) {
        goto err_out;
    }
    if (tag_len != 0) {
        if (gcry_cipher_checktag(handle, tag, tag_len)) {
            goto err_out;
        }
    }

    gcry_cipher_close(handle);
    return true;

err_out:
    gcry_cipher_close(handle);
    return false;
}

static void add_key_to_proto_tree(tvbuff_t *tvb, proto_tree* sec_tree, mbus_key_record_t* key_record)
{
    // Key
    proto_item* key_item = proto_tree_add_bytes(sec_tree, hf_mbus_sec_key, tvb, 0, MBUS_SEC_CONST_KEYSIZE, key_record->key);
    proto_item_set_generated(key_item);
    // Key Label
    proto_item* key_label_item = proto_tree_add_string(sec_tree, hf_mbus_sec_decryption_key, tvb, 0, 0, key_record->label);
    proto_item_set_generated(key_label_item);
}

static tvbuff_t* decrypt_mode9(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree, int offset, const mbus_secure_ctx_t* mbus_secure_ctx)
{
    (void)pinfo;

    proto_tree* sec_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_mbus_sec, NULL, "Security Header");

    uint8_t iv[12];
    uint8_t aad[6];
    uint8_t aad_length = 0;

    aad[aad_length++] = (uint8_t)mbus_secure_ctx->configField;
    aad[aad_length++] = (uint8_t)(mbus_secure_ctx->configField >> 8);

    // Encrypted length
    uint32_t encrypted_length;
    if ((mbus_secure_ctx->configField & MBUS_CONFIG_M9_LEN_E_BIT_MASK) == 0u) {
        proto_tree_add_item(sec_tree, hf_mbus_sec_encrypted_length, tvb, offset, 1, ENC_NA);
        encrypted_length = tvb_get_uint8(tvb, offset);
        aad[aad_length++] = tvb_get_uint8(tvb, offset);
        offset += 1;
    }
    else {
        proto_tree_add_item(sec_tree, hf_mbus_sec_encrypted_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        encrypted_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        aad[aad_length++] = tvb_get_uint8(tvb, offset);
        aad[aad_length++] = tvb_get_uint8(tvb, offset + 1);
        offset += 2;
    }

    // Unencrypted length
    uint32_t unencrypted_length;
    if ((mbus_secure_ctx->configField & MBUS_CONFIG_M9_LEN_U_BIT_MASK) == 0u) {
        proto_tree_add_item(sec_tree, hf_mbus_sec_unencrypted_length, tvb, offset, 1, ENC_NA);
        unencrypted_length = tvb_get_uint8(tvb, offset);
        aad[aad_length++] = tvb_get_uint8(tvb, offset);
        offset += 1;
    }
    else {
        proto_tree_add_item(sec_tree, hf_mbus_sec_unencrypted_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        unencrypted_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        aad[aad_length++] = tvb_get_uint8(tvb, offset);
        aad[aad_length++] = tvb_get_uint8(tvb, offset + 1);
        offset += 2;
    }

    // Tag length
    uint8_t tag_length = (mbus_secure_ctx->configField & MBUS_CONFIG_M9_AUTHENTICATION_TAG_SIZE_MASK) == 0u ? 0u : 12u;

    // IV
    // [0-3]  => Serial number
    // [4-5]  => Manufacturer ID
    // [6]    => Version
    // [7]    => Medium
    // [8-11] => Received Message Counter
    if (mbus_secure_ctx->fields_present) {
        memcpy(&iv[0], &mbus_secure_ctx->identification_number, sizeof(mbus_secure_ctx->identification_number));
        memcpy(&iv[4], &mbus_secure_ctx->manufacturer, sizeof(mbus_secure_ctx->manufacturer));
        iv[6] = mbus_secure_ctx->version;
        iv[7] = mbus_secure_ctx->device;
    }
    iv[8] = tvb_get_uint8(tvb, offset);
    iv[9] = tvb_get_uint8(tvb, offset + 1);
    iv[10] = tvb_get_uint8(tvb, offset + 2);
    iv[11] = tvb_get_uint8(tvb, offset + 3);

    proto_tree_add_item(sec_tree, hf_mbus_sec_message_counter, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    // DECRYPT
    uint8_t key[16];
    memset(key, 0xDD, sizeof(key));

    uint8_t* enc_buffer = (uint8_t *)tvb_memdup(pinfo->pool, tvb, offset, unencrypted_length + encrypted_length);
    uint8_t* dec_buffer = (uint8_t *)tvb_memdup(pinfo->pool, tvb, offset, unencrypted_length + encrypted_length);
    uint8_t* tag_buffer = (uint8_t *)tvb_memdup(pinfo->pool, tvb, offset + unencrypted_length + encrypted_length, tag_length);

    /* Loop through user's password table for preconfigured keys */
    GSList *GSList_i = mbus_pc_keyring;
    bool decrypted = false;
    while ( GSList_i && !decrypted ) {
        if (mbus_secure_ctx->fields_present == false) {
            GSList *mbus_secure_ctx_list_i = mbus_secure_ctx_list;
            while (mbus_secure_ctx_list_i && !decrypted) {
                mbus_secure_ctx_t* secure_ctx_item = (mbus_secure_ctx_t*)mbus_secure_ctx_list_i->data;

                memcpy(&iv[0], &secure_ctx_item->identification_number, sizeof(secure_ctx_item->identification_number));
                memcpy(&iv[4], &secure_ctx_item->manufacturer, sizeof(secure_ctx_item->manufacturer));
                iv[6] = secure_ctx_item->version;
                iv[7] = secure_ctx_item->device;

                decrypted = mbus_sec_gcm128_decrypt_payload(&enc_buffer[unencrypted_length], encrypted_length,
                                                            iv, sizeof(iv),
                                                            aad, aad_length,
                                                            tag_buffer, tag_length,
                                                            &dec_buffer[unencrypted_length],
                                                            (mbus_key_record_t*)(GSList_i->data));
                if (decrypted == false) {
                    mbus_secure_ctx_list_i = g_slist_next(mbus_secure_ctx_list_i);
                }
            }
        }
        else {
            decrypted = mbus_sec_gcm128_decrypt_payload(&enc_buffer[unencrypted_length], encrypted_length,
                                                        iv, sizeof(iv),
                                                        aad, aad_length,
                                                        tag_buffer, tag_length,
                                                        &dec_buffer[unencrypted_length],
                                                        (mbus_key_record_t*)(GSList_i->data));
            if (decrypted) {
                mbus_add_secure_ctx_if_not_exist(mbus_secure_ctx);
            }
        }

        if (decrypted) {
            /* TODO save information about key used so it is faster next time */
            add_key_to_proto_tree(tvb, sec_tree, (mbus_key_record_t*)(GSList_i->data));
        } else {
            GSList_i = g_slist_next(GSList_i);
        }
    }

    if (decrypted) {
        /* Found a key that worked, setup the new tvbuff_t and return */
        tvbuff_t* payload_tvb = tvb_new_child_real_data(tvb, dec_buffer, unencrypted_length + encrypted_length, unencrypted_length + encrypted_length);
        add_new_data_source(pinfo, payload_tvb, "Decrypted MBus Payload");
        return payload_tvb;
    }
    else {
        /* Add expert info. */
        expert_add_info(pinfo, sec_tree, &ei_mbus_sec_encrypted_payload);
        /* Create a buffer for the undecrypted payload. */
        tvbuff_t* payload_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset));
        /* Dump the payload to the data dissector. */
        call_data_dissector(payload_tvb, pinfo, tree);
        return NULL;
    }
}

tvbuff_t* dissect_mbus_secure(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree, int offset,
                              const mbus_secure_ctx_t* mbus_secure_ctx)
{
    switch ((mbus_secure_ctx->configField & MBUS_CONFIG_MODE_MASK) >> MBUS_CONFIG_MODE_SHIFT) {
        case 0x09:
            return decrypt_mode9(tvb, pinfo, tree, offset, mbus_secure_ctx);
        default:
            /* Add expert info. */
            proto_tree* sec_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_mbus_sec, NULL, "Security Header");
            expert_add_info(pinfo, sec_tree, &ei_mbus_sec_encrypted_payload);
            /* Create a buffer for the undecrypted payload. */
            tvbuff_t* payload_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset));
            /* Dump the payload to the data dissector. */
            call_data_dissector(payload_tvb, pinfo, tree);
            return NULL;
    }
} /* dissect_mbus_secure */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
