/* packet-mbus-apl.c
 * Routines for MBus Application Layer (APL) dissection.
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
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <wsutil/time_util.h>
#include "packet-mbus-common.h"
#include "math.h"

#define PROTO_DATA_KEY_MBUS_PACKET_INFO 0

#define mbus_dif_length_and_data_coding_names_VALUE_STRING_LIST(XXX) \
    XXX(DIF_DATA_FIELD_NO_DATA,                 0x00, "No Data") \
    XXX(DIF_DATA_FIELD_8_BIT_INTEGER,           0x01, "8 Bit Integer") \
    XXX(DIF_DATA_FIELD_16_BIT_INTEGER,          0x02, "16 Bit Integer") \
    XXX(DIF_DATA_FIELD_24_BIT_INTEGER,          0x03, "24 Bit Integer") \
    XXX(DIF_DATA_FIELD_32_BIT_INTEGER,          0x04, "32 Bit Integer") \
    XXX(DIF_DATA_FIELD_32_BIT_REAL,             0x05, "32 Bit Real") \
    XXX(DIF_DATA_FIELD_48_BIT_INTEGER,          0x06, "48 Bit Integer") \
    XXX(DIF_DATA_FIELD_64_BIT_INTEGER,          0x07, "64 Bit Integer") \
    XXX(DIF_DATA_FIELD_SELECTION_FOR_READOUT,   0x08, "Selection For Readout") \
    XXX(DIF_DATA_FIELD_2_DIGIT_BCD,             0x09, "2 Digit BCD") \
    XXX(DIF_DATA_FIELD_4_DIGIT_BCD,             0x0A, "4 Digit BCD") \
    XXX(DIF_DATA_FIELD_6_DIGIT_BCD,             0x0B, "6 Digit BCD") \
    XXX(DIF_DATA_FIELD_8_DIGIT_BCD,             0x0C, "8 Digit BCD") \
    XXX(DIF_DATA_FIELD_VARIABLE_LENGTH,         0x0D, "Variable Length") \
    XXX(DIF_DATA_FIELD_12_DIGIT_BCD,            0x0E, "12 Digit BCD") \
    XXX(DIF_DATA_FIELD_SPECIAL_FUNCTION,        0x0F, "Special Function")

VALUE_STRING_ENUM(mbus_dif_length_and_data_coding_names);
VALUE_STRING_ARRAY(mbus_dif_length_and_data_coding_names);
static value_string_ext mbus_dif_length_and_data_coding_names_ext = VALUE_STRING_EXT_INIT(mbus_dif_length_and_data_coding_names);

#define mbus_upgrade_state_names_VALUE_STRING_LIST(XXX) \
    XXX(UPGRADE_STATE_IDLE,            0x00, "Idle") \
    XXX(UPGRADE_STATE_DATA_RECEIVE,    0x01, "Data Receive") \
    XXX(UPGRADE_STATE_VALIDATING,      0x02, "Validating") \
    XXX(UPGRADE_STATE_VALIDATED,       0x03, "Validated") \
    XXX(UPGRADE_STATE_VALIDATION_FAIL, 0x04, "Validation Fail") \
    XXX(UPGRADE_STATE_ACTIVATING,      0x05, "Activating") \
    XXX(UPGRADE_STATE_ACTIVATED,       0x06, "Activated") \
    XXX(UPGRADE_STATE_ACTIVATION_FAIL, 0x07, "Activation Fail") \
    XXX(UPGRADE_STATE_CANCELLING,      0x08, "Cancelling") \
    XXX(UPGRADE_STATE_ERROR,           0x09, "Error")

VALUE_STRING_ENUM(mbus_upgrade_state_names);
VALUE_STRING_ARRAY(mbus_upgrade_state_names);
static value_string_ext mbus_upgrade_state_names_ext = VALUE_STRING_EXT_INIT(mbus_upgrade_state_names);

#define mbus_ita_function_field_names_VALUE_STRING_LIST(XXX) \
    XXX(ITA_FUNCTION_PREPARE,                0x00, "Prepare") \
    XXX(ITA_FUNCTION_SYNCHRONIZE,            0x01, "Synchronize") \
    XXX(ITA_FUNCTION_TRANSFER,               0x02, "Transfer") \
    XXX(ITA_FUNCTION_COMPLETION,             0x03, "Completion") \
    XXX(ITA_FUNCTION_STATE,                  0x04, "State") \
    XXX(ITA_FUNCTION_VALIDATE,               0x05, "Validate") \
    XXX(ITA_FUNCTION_ACTIVATE,               0x06, "Activate") \
    XXX(ITA_FUNCTION_TERMINATE,              0x07, "Terminate") \
    XXX(ITA_FUNCTION_ACTIVE_IMAGES,          0x08, "Active Images") \
    XXX(ITA_FUNCTION_PREPARE_RESPONSE,       0x80, "Prepare Response") \
    XXX(ITA_FUNCTION_SYNCHRONIZE_RESPONSE,   0x81, "Synchronize Response") \
    XXX(ITA_FUNCTION_TRANSFER_RESPONSE,      0x82, "Transfer Response") \
    XXX(ITA_FUNCTION_COMPLETION_RESPONSE,    0x83, "Completion Response") \
    XXX(ITA_FUNCTION_STATE_RESPONSE,         0x84, "State Response") \
    XXX(ITA_FUNCTION_VALIDATE_RESPONSE,      0x85, "Validate Response") \
    XXX(ITA_FUNCTION_ACTIVATE_RESPONSE,      0x86, "Activate Response") \
    XXX(ITA_FUNCTION_TERMINATE_RESPONSE,     0x87, "Terminate Response") \
    XXX(ITA_FUNCTION_ACTIVE_IMAGES_RESPONSE, 0x88, "Active Images Response")

VALUE_STRING_ENUM(mbus_ita_function_field_names);
VALUE_STRING_ARRAY(mbus_ita_function_field_names);
static value_string_ext mbus_ita_function_field_names_ext = VALUE_STRING_EXT_INIT(mbus_ita_function_field_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_mbus_apl(void);
void proto_reg_handoff_mbus_apl(void);

/* Command Dissector Helpers */
static void dissect_mbus_dif_vif(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_mbus_time_sync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_mbus_image_transfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*************************/
/** Global Variables    **/
/*************************/
/* Dissector Handles. */
static dissector_handle_t mbus_apl_handle;
static dissector_handle_t dtls_handle;

/* Heuristic Subdissector List */
static heur_dissector_list_t heur_subdissector_list;

/* Initialize the protocol and registered fields */
static int proto_mbus_apl;

static int hf_mbus_dif;
static int hf_mbus_dif_length_and_data_coding;
static int hf_mbus_dif_function_field;
static int hf_mbus_dif_lsb_of_storage_number;
static int hf_mbus_dif_extended_bit;
static int hf_mbus_dife;
static int hf_mbus_dife_storage_number;
static int hf_mbus_dife_tariff;
static int hf_mbus_dife_device_unit;
static int hf_mbus_dife_extended_bit;
static int hf_mbus_vif;
static int hf_mbus_vife;
static int hf_mbus_lvar;
static int hf_mbus_dif_vif_data;
static int hf_mbus_dif_vif_data_uint8;
static int hf_mbus_dif_vif_data_uint16;
static int hf_mbus_dif_vif_data_uint24;
static int hf_mbus_dif_vif_data_uint32;
static int hf_mbus_dif_vif_data_uint48;
static int hf_mbus_dif_vif_data_uint64;
static int hf_mbus_time_sync_tc;
static int hf_mbus_time_sync_date_time;
static int hf_mbus_ita_segment_length;
static int hf_mbus_ita_segment_id;
static int hf_mbus_ita_segment_function_field;
static int hf_mbus_ita_segment_sub_function_field;
static int hf_mbus_ita_segment_payload;

// "Special" VIFs
static int hf_mbus_vif_bytes;
static int hf_mbus_vif_string;
static int hf_mbus_vif_upgrade_size;
static int hf_mbus_vif_upgrade_state;
static int hf_mbus_vif_upgrade_error_code;
static int hf_mbus_vif_upgrade_block_size;
static int hf_mbus_vif_upgrade_status_validation_field;
static int hf_mbus_vif_upgrade_data;
static int hf_mbus_vif_upgrade_validate;
static int hf_mbus_vif_upgrade_activate;
static int hf_mbus_vif_upgrade_cancel;
static int hf_mbus_vif_upgrade_block_status;

/* Initialize the subtree pointers */
#define MBUS_NUM_INDIVIDUAL_ETT                 5
#define MBUS_NUM_MBUS_APP_BLOCK_ETT             10
#define MBUS_NUM_TOTAL_ETT                      (MBUS_NUM_INDIVIDUAL_ETT + MBUS_NUM_MBUS_APP_BLOCK_ETT)

static int ett_mbus_apl;
static int ett_mbus_dif;
static int ett_mbus_dife;
static int ett_mbus_vif;
static int ett_mbus_vife;
static int ett_mbus_long_frame_app_block[MBUS_NUM_MBUS_APP_BLOCK_ETT];

/* MBus DIF */
#define MBUS_DIF_LENGTH_AND_DATA_CODING_MASK    0x0F
#define MBUS_DIF_FUNCTION_FIELD_MASK            0x30
#define MBUS_DIF_LSB_OF_STORAGE_NUMBER_MASK     0x40
#define MBUS_DIF_EXTENDED_BIT_MASK              0x80

static int* const dif_flags[] = {
    &hf_mbus_dif_length_and_data_coding,
    &hf_mbus_dif_function_field,
    &hf_mbus_dif_lsb_of_storage_number,
    &hf_mbus_dif_extended_bit,
    NULL
};

/* MBus DIFE */
#define MBUS_DIFE_STORAGE_NUMBER_MASK           0x0F
#define MBUS_DIFE_TARIFF_MASK                   0x30
#define MBUS_DIFE_DEVICE_UNIT_MASK              0x40
#define MBUS_DIFE_EXTENDED_BIT_MASK             0x80

static int* const dife_flags[] = {
    &hf_mbus_dife_storage_number,
    &hf_mbus_dife_tariff,
    &hf_mbus_dife_device_unit,
    &hf_mbus_dife_extended_bit,
    NULL
};

static void convert_date_format_i_to_time(tvbuff_t *tvb, int offset, nstime_t* date_time)
{
    bool leap_year = (tvb_get_uint8(tvb, offset) & 0x80u) != 0u;
    bool time_valid = (tvb_get_uint8(tvb, offset + 1u) & 0x80u) == 0u;
    (void)leap_year;
    (void)time_valid;

    struct tm tm;
    tm.tm_yday = 0;
    tm.tm_isdst = -1;

    tm.tm_sec = tvb_get_uint8(tvb, offset) & 0x3Fu;
    tm.tm_min = tvb_get_uint8(tvb, offset + 1) & 0x3Fu;
    tm.tm_hour = tvb_get_uint8(tvb, offset + 2) & 0x1Fu;
    tm.tm_wday = (tvb_get_uint8(tvb, offset + 2) & 0xE0u) >> 5;
    tm.tm_mday = tvb_get_uint8(tvb, offset + 3) & 0x1Fu;
    tm.tm_mon = (tvb_get_uint8(tvb, offset + 4) & 0x0Fu) - 1;
    tm.tm_year = ((tvb_get_uint8(tvb, offset + 3) & 0xE0u) >> 5) +
                 ((tvb_get_uint8(tvb, offset + 4) & 0xF0u) >> 1);
    tm.tm_year += 2000 - 1900;

    date_time->secs = mktime_utc(&tm);
    date_time->nsecs = 0;
}

static bool is_dtls_channel_request(const mbus_packet_info_t* mbus_info)
{
    uint8_t encryptionMode = (mbus_info->security_info.configField & MBUS_CONFIG_MODE_MASK) >> MBUS_CONFIG_MODE_SHIFT;
    return encryptionMode == 13 && mbus_info->security_info.configFieldExtension == 0;
}

static bool check_dtls_record(const mbus_packet_info_t* mbus_info)
{
    // Check if this is a TLS record by looking at the encryption mode.
    // TLS is indicated by encryption mode 13. If the encryption mode is 13,
    // but the config field extension is 0, then this is a TLS Channel Request, not an actual TLS record.
    uint8_t encryptionMode = (mbus_info->security_info.configField & MBUS_CONFIG_MODE_MASK) >> MBUS_CONFIG_MODE_SHIFT;
    if (encryptionMode != 13) {
        return false;
    }

    if (mbus_info->security_info.configFieldExtension == 0) {
        // TLS Channel Request
        return false;
    }

    return true;
}

static void decode_mbus_bcd_encoded_data(tvbuff_t *tvb, proto_tree *tree, int offset, int size, double scaler)
{
    uint8_t bcd;
    uint8_t dec;
    double value = 0;
    uint64_t multiplier = 1;
    for (int i = 0; i < size; i++) {
        bcd = tvb_get_uint8(tvb, offset + i);
        dec = bcd & 0xF;
        dec += (bcd >> 4) * 10;
        uint64_t b = dec * multiplier;
        multiplier *= 100;
        value += b;
    }
    value *= scaler;
    proto_tree_add_bytes_format_value(tree, hf_mbus_dif_vif_data, tvb, offset, size, NULL, "%f", value);
}

typedef struct {
    uint8_t vif;
    uint8_t n_minus;
    uint8_t range;
} vif_scaler_t;

static double get_vif_scaler(uint8_t vif_primary)
{
    static const vif_scaler_t vif_scalings[] = {
        { 0x00, 3, 7 }, // Energy
        { 0x08, 0, 7 }, // Energy
        { 0x10, 6, 7 }, // Volume
        { 0x18, 3, 7 }, // Mass
        { 0x20, 0, 3 }, // On time
        { 0x28, 0, 7 }, // Operating time
        { 0x30, 3, 7 }, // Power
        { 0x38, 0, 7 }, // Power
        { 0x40, 6, 7 }, // Volume flow
        { 0x48, 7, 7 }, // Volume flow ext
        { 0x50, 9, 7 }, // Volume flow ext
        { 0x58, 3, 3 }, // Mass flow
        { 0x5C, 3, 3 }, // Flow temperature
        { 0x60, 3, 3 }, // Return temperature
        { 0x64, 3, 3 }, // Temperature difference
        { 0x68, 3, 3 }, // External temperature
        { 0x6C, 3, 3 }, // Pressure
        { 0x6D, 0, 0 }, // Date
        { 0x6E, 0, 0 }, // Date
        { 0x6F, 0, 0 }, // Units for HCA
        { 0x70, 0, 3 }, // Averaging duration
        { 0x74, 0, 3 }, // Actuality duration
        { 0x78, 0, 0 }, // Fabrication no
        { 0x79, 0, 0 }, // Enhanced identification
        { 0x7A, 0, 0 }, // Address
        { 0x7C, 0, 0 }, // Vif in following string
        { 0x7E, 0, 0 }, // Any vif
        { 0x7F, 0, 0 }  // Manufacturer specific
    };

    double scaling = 1;
    uint8_t vif = vif_primary & 0x7F;
    for (size_t i = 0; i < array_length(vif_scalings); ++i) {
        if ((vif >= vif_scalings[i].vif) && (vif <= vif_scalings[i].vif + vif_scalings[i].range)) {
            uint8_t delta = vif - vif_scalings[i].vif;
            scaling = pow(10, delta);
            scaling /= pow(10, vif_scalings[i].n_minus);
        }
    }
    return scaling;
}

typedef void (*mbus_data_handler_t)(tvbuff_t *tvb, proto_tree *tree, int offset, int size);

typedef struct {
    bytes_string vif;
    mbus_data_handler_t handler;
} vif_data_handler_t;

static void handle_date_time(tvbuff_t *tvb, proto_tree *tree, int offset, int size _U_)
{
    // Timestamp format I
    nstime_t date_time;
    convert_date_format_i_to_time(tvb, offset, &date_time);
    proto_tree_add_time(tree, hf_mbus_time_sync_date_time, tvb, offset, 6, &date_time);
}

static void handle_mbus_fw_upgrade_start(tvbuff_t *tvb, proto_tree *tree, int offset, int size _U_)
{
    proto_tree_add_item(tree, hf_mbus_lvar, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_block_size, tvb, offset, 1, ENC_NA);
}

static void handle_mbus_fw_upgrade_status(tvbuff_t *tvb, proto_tree *tree, int offset, int size _U_)
{
    proto_tree_add_item(tree, hf_mbus_lvar, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_state, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_error_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_block_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    uint8_t validation_field_length = tvb_get_uint8(tvb, offset);
    offset += 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_status_validation_field, tvb, offset, validation_field_length, ENC_NA);
}

static void handle_mbus_fw_upgrade_data(tvbuff_t *tvb, proto_tree *tree, int offset, int size)
{
    proto_tree_add_item(tree, hf_mbus_lvar, tvb, offset, 1, ENC_NA);
    offset += 1;
    size -= 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_data, tvb, offset, size, ENC_NA);
}

static void handle_mbus_fw_upgrade_validate(tvbuff_t *tvb, proto_tree *tree, int offset, int size)
{
    proto_tree_add_item(tree, hf_mbus_lvar, tvb, offset, 1, ENC_NA);
    offset += 1;
    size -= 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_validate, tvb, offset, size, ENC_NA);
}

static void handle_mbus_fw_upgrade_activate(tvbuff_t *tvb, proto_tree *tree, int offset, int size)
{
    proto_tree_add_item(tree, hf_mbus_lvar, tvb, offset, 1, ENC_NA);
    offset += 1;
    size -= 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_activate, tvb, offset, size, ENC_NA);
}

static void handle_mbus_fw_upgrade_cancel(tvbuff_t *tvb, proto_tree *tree, int offset, int size)
{
    proto_tree_add_item(tree, hf_mbus_lvar, tvb, offset, 1, ENC_NA);
    offset += 1;
    size -= 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_cancel, tvb, offset, size, ENC_NA);
}

static void handle_mbus_fw_upgrade_block_status(tvbuff_t *tvb, proto_tree *tree, int offset, int size)
{
    proto_tree_add_item(tree, hf_mbus_lvar, tvb, offset, 1, ENC_NA);
    offset += 1;
    size -= 1;
    proto_tree_add_item(tree, hf_mbus_vif_upgrade_block_status, tvb, offset, size, ENC_NA);
}

static const uint8_t special_vif_time[] = { 0x6D };
static const uint8_t special_vif_fw_upgrade_start[] = { 0xFD, 0xF7, 0x30 };
static const uint8_t special_vif_fw_upgrade_status[] = { 0xFD, 0xF7, 0x31 };
static const uint8_t special_vif_fw_upgrade_data[] = { 0xFD, 0xF7, 0x32 };
static const uint8_t special_vif_fw_upgrade_validate[] = { 0xFD, 0xF7, 0x33 };
static const uint8_t special_vif_fw_upgrade_activate[] = { 0xFD, 0xF7, 0x34 };
static const uint8_t special_vif_fw_upgrade_cancel[] = { 0xFD, 0xF7, 0x35 };
static const uint8_t special_vif_fw_upgrade_block_status[] = { 0xFD, 0xF7, 0x36 };

static const vif_data_handler_t vif_data_handlers[] = {
    {{ special_vif_time, sizeof(special_vif_time), "Time" }, handle_date_time },
    {{ special_vif_fw_upgrade_start, sizeof(special_vif_fw_upgrade_start), "Upgrade Start" }, handle_mbus_fw_upgrade_start },
    {{ special_vif_fw_upgrade_status, sizeof(special_vif_fw_upgrade_status), "Upgrade Status" }, handle_mbus_fw_upgrade_status },
    {{ special_vif_fw_upgrade_data, sizeof(special_vif_fw_upgrade_data), "Upgrade Data" }, handle_mbus_fw_upgrade_data },
    {{ special_vif_fw_upgrade_validate, sizeof(special_vif_fw_upgrade_validate), "Upgrade Validate" }, handle_mbus_fw_upgrade_validate },
    {{ special_vif_fw_upgrade_activate, sizeof(special_vif_fw_upgrade_activate), "Upgrade Activate" }, handle_mbus_fw_upgrade_activate },
    {{ special_vif_fw_upgrade_cancel, sizeof(special_vif_fw_upgrade_cancel), "Upgrade Cancel" }, handle_mbus_fw_upgrade_cancel },
    {{ special_vif_fw_upgrade_block_status, sizeof(special_vif_fw_upgrade_block_status), "Upgrade Block Status" }, handle_mbus_fw_upgrade_block_status }
};

static uint8_t get_vif_length(tvbuff_t *tvb, int vif_offset)
{
    uint8_t dif_vif;
    int i = 0;
    do {
        dif_vif = tvb_get_uint8(tvb, vif_offset + i);
        i++;
    } while((dif_vif & 0x80) != 0);
    return (uint8_t)i;
}

static int get_data_length_from_dif_length_and_data_encoding(tvbuff_t *tvb, int offset, uint8_t dif_length_and_data_encoding)
{
    int data_length = 0;
    switch (dif_length_and_data_encoding) {
        case DIF_DATA_FIELD_NO_DATA:
            data_length = 0;
            break;
        case DIF_DATA_FIELD_8_BIT_INTEGER:
            data_length = 1;
            break;
        case DIF_DATA_FIELD_16_BIT_INTEGER:
            data_length = 2;
            break;
        case DIF_DATA_FIELD_24_BIT_INTEGER:
            data_length = 3;
            break;
        case DIF_DATA_FIELD_32_BIT_INTEGER:
        case DIF_DATA_FIELD_32_BIT_REAL:
            data_length = 4;
            break;
        case DIF_DATA_FIELD_48_BIT_INTEGER:
            data_length = 6;
            break;
        case DIF_DATA_FIELD_64_BIT_INTEGER:
            data_length = 8;
            break;
        case DIF_DATA_FIELD_SELECTION_FOR_READOUT:
            data_length = 0;
            break;
        case DIF_DATA_FIELD_2_DIGIT_BCD:
            data_length = 1;
            break;
        case DIF_DATA_FIELD_4_DIGIT_BCD:
            data_length = 2;
            break;
        case DIF_DATA_FIELD_6_DIGIT_BCD:
            data_length = 3;
            break;
        case DIF_DATA_FIELD_8_DIGIT_BCD:
            data_length = 4;
            break;
        case DIF_DATA_FIELD_VARIABLE_LENGTH: {
            uint8_t lvar = tvb_get_uint8(tvb, offset);
            if (lvar < 0xC0) {
                data_length = lvar + 1;
            }
            else if (lvar >= 0xC0 && lvar <= 0xC9) {
                data_length = (lvar - 0xC0) + 1;
            }
            else if (lvar >= 0xD0 && lvar <= 0xDF) {
                data_length = (lvar - 0xD0) + 1;
            }
            else if (lvar >= 0xE0 && lvar <= 0xEF) {
                data_length = (lvar - 0xE0) + 1;
            }
            else if (lvar >= 0xF0 && lvar <= 0xF4) {
                data_length = ((lvar - 0xEC) * 4) + 1;
            }
            else if (lvar == 0xF5) {
                data_length = 48 + 1;
            }
            else if (lvar == 0xF6) {
                data_length = 64 + 1;
            }
            else {
                data_length = 0xFF;
            }
            break;
        }
        case DIF_DATA_FIELD_12_DIGIT_BCD:
            data_length = 6;
            break;
        case DIF_DATA_FIELD_SPECIAL_FUNCTION:
        default:
            data_length = 0xFF;
            break;
    }
    return data_length;
}

static bool dissect_special_vif(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int* offset, uint8_t dif_length_and_data_encoding)
{
    bool match = false;
    uint8_t vif_length = get_vif_length(tvb, *offset);

    // Manually loop over the handles because we don't have an array of bytes_string.
    // If we went for that, then we couldn't have function pointers in the same struct.
    for (size_t i = 0; i < array_length(vif_data_handlers); i++) {
        match = vif_data_handlers[i].vif.value_length == vif_length;
        if (!match) {
            continue;
        }

        const uint8_t* vif_bytes = tvb_get_ptr(tvb, *offset, vif_length);
        match = memcmp(vif_data_handlers[i].vif.value, vif_bytes, vif_length) == 0;

        if (match) {
            // VIF item
            proto_item* item = proto_tree_add_item(tree, hf_mbus_vif_bytes, tvb, *offset, vif_length, ENC_NA);
            if (vif_data_handlers[i].vif.strptr != NULL) {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", vif_data_handlers[i].vif.strptr);
                proto_item_append_text(item, " (%s)", vif_data_handlers[i].vif.strptr);
            }
            // Move offset past VIF(s)
            *offset += vif_length;
            // Call the handler. Only makes sense if it is not a selection for readout
            int data_length = get_data_length_from_dif_length_and_data_encoding(tvb, *offset, dif_length_and_data_encoding);
            if (dif_length_and_data_encoding != DIF_DATA_FIELD_SELECTION_FOR_READOUT) {
                vif_data_handlers[i].handler(tvb, tree, *offset, data_length);
            }
            // Increment offset according to data length
            *offset += data_length;
            // Stop processing
            break;
        }
    }

    return match;
}

static void dissect_generic_vif(tvbuff_t *tvb, proto_tree *tree, int* offset, uint8_t dif_length_and_data_encoding)
{
    uint8_t dif_vif;
    uint8_t vif_primary = 0;
    double vif_scaler = 1.0;

    // VIF(e)
    int i = 0;
    do {
        if (i == 0) {
            vif_primary = tvb_get_uint8(tvb, *offset);
            vif_scaler = get_vif_scaler(vif_primary);
            proto_tree_add_item(tree, hf_mbus_vif, tvb, *offset, 1, ENC_NA);
        }
        else {
            // todo We need different vife fields if we want some text to show what vif it is
            proto_tree_add_item(tree, hf_mbus_vife, tvb, *offset, 1, ENC_NA);
        }
        i++;
        dif_vif = tvb_get_uint8(tvb, *offset);
        *offset += 1;
    } while((dif_vif & 0x80) != 0);

    // Data
    int data_length = get_data_length_from_dif_length_and_data_encoding(tvb, *offset, dif_length_and_data_encoding);
    switch (dif_length_and_data_encoding) {
        case DIF_DATA_FIELD_8_BIT_INTEGER:
            proto_tree_add_item(tree, hf_mbus_dif_vif_data_uint8, tvb, *offset, data_length, ENC_LITTLE_ENDIAN);
            break;
        case DIF_DATA_FIELD_16_BIT_INTEGER:
            proto_tree_add_item(tree, hf_mbus_dif_vif_data_uint16, tvb, *offset, data_length, ENC_LITTLE_ENDIAN);
            break;
        case DIF_DATA_FIELD_24_BIT_INTEGER:
            proto_tree_add_item(tree, hf_mbus_dif_vif_data_uint24, tvb, *offset, data_length, ENC_LITTLE_ENDIAN);
            break;
        case DIF_DATA_FIELD_32_BIT_INTEGER:
        case DIF_DATA_FIELD_32_BIT_REAL:
            proto_tree_add_item(tree, hf_mbus_dif_vif_data_uint32, tvb, *offset, data_length, ENC_LITTLE_ENDIAN);
            break;
        case DIF_DATA_FIELD_48_BIT_INTEGER:
            proto_tree_add_item(tree, hf_mbus_dif_vif_data_uint48, tvb, *offset, data_length, ENC_LITTLE_ENDIAN);
            break;
        case DIF_DATA_FIELD_64_BIT_INTEGER:
            proto_tree_add_item(tree, hf_mbus_dif_vif_data_uint64, tvb, *offset, data_length, ENC_LITTLE_ENDIAN);
            break;
        case DIF_DATA_FIELD_2_DIGIT_BCD:
            decode_mbus_bcd_encoded_data(tvb, tree, *offset, data_length, vif_scaler);
            break;
        case DIF_DATA_FIELD_4_DIGIT_BCD:
            decode_mbus_bcd_encoded_data(tvb, tree, *offset, data_length, vif_scaler);
            break;
        case DIF_DATA_FIELD_6_DIGIT_BCD:
            decode_mbus_bcd_encoded_data(tvb, tree, *offset, data_length, vif_scaler);
            break;
        case DIF_DATA_FIELD_8_DIGIT_BCD:
            decode_mbus_bcd_encoded_data(tvb, tree, *offset, data_length, vif_scaler);
            break;
        default:
            proto_tree_add_item(tree, hf_mbus_dif_vif_data, tvb, *offset, data_length, ENC_NA);
            break;
    }

    *offset += data_length;
}

/**
 *This function manages mbus dif vif
 *
 *@param tvb pointer to buffer containing raw packet
 *@param pinfo pointer to packet info
 *@param tree pointer to data tree Wireshark uses to display packet
*/
static void
dissect_mbus_dif_vif(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int i = 0;
    int offset = 0;
    int record_count = 0;
    uint8_t dif_vif;
    uint8_t dif_length_and_data_encoding = 0;

    while (tvb_reported_length_remaining(tvb, offset) > 0 && record_count < MBUS_NUM_MBUS_APP_BLOCK_ETT) {
        proto_tree* app_block_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_mbus_long_frame_app_block[record_count],
                                                                   NULL, "Data Record %d", record_count + 1);
        record_count++;

        // DIF(e)
        i = 0;
        do {
            if (i == 0) {
                dif_length_and_data_encoding = tvb_get_uint8(tvb, offset) & MBUS_DIF_LENGTH_AND_DATA_CODING_MASK;
                proto_tree_add_bitmask(app_block_tree, tvb, offset, hf_mbus_dif, ett_mbus_dif, dif_flags, ENC_NA);
            }
            else {
                proto_tree_add_bitmask(app_block_tree, tvb, offset, hf_mbus_dife, ett_mbus_dife, dife_flags, ENC_NA);
            }
            i++;
            dif_vif = tvb_get_uint8(tvb, offset);
            offset += 1;
        } while(dif_vif & 0x80);

        // Some combinations of VIF(e) has special meaning. Handle those first.
        if (dissect_special_vif(tvb, pinfo, app_block_tree, &offset, dif_length_and_data_encoding) == false) {
            dissect_generic_vif(tvb, app_block_tree, &offset, dif_length_and_data_encoding);
        }

        // Set end of data record
        proto_item_set_end(proto_tree_get_parent(app_block_tree), tvb, offset);
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "(Total Records %d)", record_count);
}

/**
 *This function manages mbus time sync (CI Field 0x6C)
 *
 *@param tvb pointer to buffer containing raw packet
 *@param pinfo pointer to packet info
 *@param tree pointer to data tree Wireshark uses to display packet
*/
static void
dissect_mbus_time_sync(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    if (tvb_reported_length(tvb) != 14) {
        return;
    }

    proto_tree_add_item(tree, hf_mbus_time_sync_tc, tvb, offset, 1, ENC_NA);
    offset += 1;

    nstime_t date_time;
    convert_date_format_i_to_time(tvb, offset, &date_time);

    proto_tree_add_time(tree, hf_mbus_time_sync_date_time, tvb, offset, 6, &date_time);
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Time sync");
}

static void dissect_mbus_image_transfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_mbus_ita_segment_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_mbus_ita_segment_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    uint8_t function_field = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mbus_ita_segment_function_field, tvb, offset, 1, ENC_NA);
    offset += 1;

    // TODO Create different dissectors for each function field and call them from here.
    // uint8_t sub_function_field = tvb_get_uint8(tvb, offset);

    // switch (function_field) {
    //     case ITA_FUNCTION_PREPARE:
    //         break;
    //     case ITA_FUNCTION_SYNCHRONIZE:
    //         break;
    //     case ITA_FUNCTION_TRANSFER:
    //         break;
    //     case ITA_FUNCTION_COMPLETION:
    //         break;
    //     case ITA_FUNCTION_STATE:
    //         break;
    //     case ITA_FUNCTION_VALIDATE:
    //         break;
    //     case ITA_FUNCTION_ACTIVATE:
    //         break;
    //     case ITA_FUNCTION_TERMINATE:
    //         break;
    //     case ITA_FUNCTION_ACTIVE_IMAGES:
    //         break;
    //     case ITA_FUNCTION_PREPARE_RESPONSE:
    //         break;
    //     case ITA_FUNCTION_SYNCHRONIZE_RESPONSE:
    //         break;
    //     case ITA_FUNCTION_TRANSFER_RESPONSE:
    //         break;
    //     case ITA_FUNCTION_COMPLETION_RESPONSE:
    //         break;
    //     case ITA_FUNCTION_STATE_RESPONSE:
    //         break;
    //     case ITA_FUNCTION_VALIDATE_RESPONSE:
    //         break;
    //     case ITA_FUNCTION_ACTIVATE_RESPONSE:
    //         break;
    //     case ITA_FUNCTION_TERMINATE_RESPONSE:
    //         break;
    //     case ITA_FUNCTION_ACTIVE_IMAGES_RESPONSE:
    //         break;
    //     default:
    //         break;
    // }

    proto_tree_add_item(tree, hf_mbus_ita_segment_sub_function_field, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_mbus_ita_segment_payload, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Image transfer, %s", val_to_str_const(function_field, mbus_ita_function_field_names, "Unknown Cmd"));
}

static int dissect_mbus_apl_helper(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mbus_packet_info_t* mbus_info)
{
    /* Create the protocol tree */
    proto_item* proto_root = proto_tree_add_protocol_format(tree, proto_mbus_apl, tvb, 0, -1, "MBus Application Layer");
    proto_tree* apl_tree = proto_item_add_subtree(proto_root, ett_mbus_apl);

    if (mbus_info->ciField == TimeSyncToDeviceLongHeader_1) {
        dissect_mbus_time_sync(tvb, pinfo, apl_tree);
    }
    else if (mbus_is_image_transfer_ci_field(mbus_info->ciField)) {
        dissect_mbus_image_transfer(tvb, pinfo, apl_tree);
    }
    else if (is_dtls_channel_request(mbus_info)) {
        // TLS Channel Request... TODO
        call_data_dissector(tvb, pinfo, apl_tree);
    }
    else {
        uint8_t first_dif = tvb_get_uint8(tvb, 0);
        if ((first_dif & 0x0F) == 0x0F) {
            proto_tree_add_bitmask(apl_tree, tvb, 0, hf_mbus_dif, ett_mbus_dif, dif_flags, ENC_NA);

            // Try heuristic dissector. Create new subset tvb without the first byte (DIF)
            heur_dtbl_entry_t* hdtbl_entry = NULL;
            tvbuff_t* tvb_no_dif = tvb_new_subset_length(tvb, 1, tvb_reported_length_remaining(tvb, 1));
            bool dissected = dissector_try_heuristic(heur_subdissector_list, tvb_no_dif, pinfo, proto_tree_get_root(tree), &hdtbl_entry, NULL);
            if (!dissected) {
                // Fallback to data dissector
                call_data_dissector(tvb_no_dif, pinfo, apl_tree);
            }
        }
        else {
            dissect_mbus_dif_vif(tvb, pinfo, apl_tree);
        }
    }

    return tvb_captured_length(tvb);
}

static void add_ci_field_proto_data(packet_info *pinfo, mbus_packet_info_t* data)
{
    mbus_packet_info_t* data_ptr = wmem_new(pinfo->pool, mbus_packet_info_t);
    *data_ptr = *data;
    p_set_proto_data(pinfo->pool, pinfo, proto_mbus_apl, PROTO_DATA_KEY_MBUS_PACKET_INFO, data_ptr);
}

static int dissect_mbus_apl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    mbus_packet_info_t* apl_data = data;
    add_ci_field_proto_data(pinfo, apl_data);

    if (check_dtls_record(apl_data)) {
        if (dtls_handle != NULL) {
            call_dissector(dtls_handle, tvb, pinfo, proto_tree_get_root(tree));
        }
        return tvb_captured_length(tvb);
    }

    return dissect_mbus_apl_helper(tvb, pinfo, tree, apl_data);
}

static bool dissect_mbus_apl_heur_dtls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    mbus_packet_info_t* apl_data = (mbus_packet_info_t*)p_get_proto_data(pinfo->pool, pinfo, proto_mbus_apl, PROTO_DATA_KEY_MBUS_PACKET_INFO);
    if (apl_data == NULL) {
        // No APL data found. This cannot be a valid MBus APL packet
        return false;
    }

    if (dissect_mbus_apl_helper(tvb, pinfo, tree, apl_data) == 0) {
        // Not a valid MBus APL packet
        return false;
    }
    return true;
}

void proto_register_mbus_apl(void)
{
    static hf_register_info hf[] = {
        { &hf_mbus_dif,
            { "Data Information Field", "mbus.apl.app_block.dif", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dif_length_and_data_coding,
            { "Length And Data Coding", "mbus.apl.app_block.dif.len_and_data_coding", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mbus_dif_length_and_data_coding_names_ext,
              MBUS_DIF_LENGTH_AND_DATA_CODING_MASK, NULL, HFILL } },
        { &hf_mbus_dif_function_field,
            { "Function Field", "mbus.apl.app_block.dif.function_field", FT_UINT8, BASE_HEX, NULL,
              MBUS_DIF_FUNCTION_FIELD_MASK, NULL, HFILL } },
        { &hf_mbus_dif_lsb_of_storage_number,
            { "LSB Of Storage Number", "mbus.apl.app_block.dif.lsb_storage_number", FT_UINT8, BASE_HEX, NULL,
              MBUS_DIF_LSB_OF_STORAGE_NUMBER_MASK, NULL, HFILL } },
        { &hf_mbus_dif_extended_bit,
            { "Extended", "mbus.apl.app_block.dif.extended", FT_BOOLEAN, 8, NULL,
              MBUS_DIF_EXTENDED_BIT_MASK, NULL, HFILL } },

        { &hf_mbus_dife,
            { "Data Information Field Extended", "mbus.apl.app_block.dife", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dife_storage_number,
            { "Storage Number", "mbus.apl.app_block.dife.storage_number", FT_UINT8, BASE_HEX, NULL,
              MBUS_DIFE_STORAGE_NUMBER_MASK, NULL, HFILL } },
        { &hf_mbus_dife_tariff,
            { "Tariff", "mbus.apl.app_block.dife.tariff", FT_UINT8, BASE_HEX, NULL,
              MBUS_DIFE_TARIFF_MASK, NULL, HFILL } },
        { &hf_mbus_dife_device_unit,
            { "Device Unit", "mbus.apl.app_block.dife.device_unit", FT_UINT8, BASE_HEX, NULL,
              MBUS_DIFE_DEVICE_UNIT_MASK, NULL, HFILL } },
        { &hf_mbus_dife_extended_bit,
            { "Extended", "mbus.apl.app_block.dife.extended", FT_UINT8, BASE_HEX, NULL,
              MBUS_DIFE_EXTENDED_BIT_MASK, NULL, HFILL } },

        { &hf_mbus_vif,
            { "Value Information Field", "mbus.apl.app_block.vif", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_vife,
            { "Value Information Field Extended", "mbus.apl.app_block.vife", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_lvar,
            { "LVAR", "mbus.apl.app_block.lvar", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_dif_vif_data,
            { "Data", "mbus.apl.app_block.data", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dif_vif_data_uint8,
            { "Data", "mbus.apl.app_block.data_uint8", FT_UINT8, BASE_DEC, NULL,
               0x00, NULL, HFILL } },
        { &hf_mbus_dif_vif_data_uint16,
            { "Data", "mbus.apl.app_block.data_uint16", FT_UINT16, BASE_DEC, NULL,
               0x00, NULL, HFILL } },
        { &hf_mbus_dif_vif_data_uint24,
            { "Data", "mbus.apl.app_block.data_uint24", FT_UINT24, BASE_DEC, NULL,
               0x00, NULL, HFILL } },
        { &hf_mbus_dif_vif_data_uint32,
            { "Data", "mbus.apl.app_block.data_uint32", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dif_vif_data_uint48,
            { "Data", "mbus.apl.app_block.data_uint48", FT_UINT48, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dif_vif_data_uint64,
            { "Data", "mbus.apl.app_block.data_uint64", FT_UINT64, BASE_DEC, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_time_sync_tc,
            { "TC", "mbus.apl.app_block.time_sync.tc", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_time_sync_date_time,
            { "Date Time", "mbus.apl.app_block.time_sync.date_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
              0x00, NULL, HFILL} },

        { &hf_mbus_vif_bytes,
            { "VIF", "mbus.apl.app_block.vif_bytes", FT_BYTES, BASE_NONE, NULL,
                0x00, NULL, HFILL }},
        { &hf_mbus_vif_string,
            { "VIF", "mbus.apl.app_block.vif_string", FT_STRING, BASE_NONE, NULL,
                0x00, NULL, HFILL }},

        { &hf_mbus_vif_upgrade_size,
            { "Upgrade Size", "mbus.apl.app_block.upgrade.size", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_vif_upgrade_state,
            { "Upgrade State", "mbus.apl.app_block.upgrade.state", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &mbus_upgrade_state_names_ext,
              0x00, NULL, HFILL } },
        { &hf_mbus_vif_upgrade_error_code,
            { "Upgrade Error Code", "mbus.apl.app_block.upgrade.error_code", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_vif_upgrade_block_size,
            { "Upgrade Block Size", "mbus.apl.app_block.upgrade.block_size", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_vif_upgrade_status_validation_field,
            { "Upgrade Validation Field", "mbus.apl.app_block.upgrade.validation_field", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_vif_upgrade_data,
            { "Upgrade Data", "mbus.apl.app_block.vif_upgrade_data", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_vif_upgrade_validate,
            { "Upgrade Validate", "mbus.apl.app_block.vif_upgrade_validate", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_vif_upgrade_activate,
            { "Upgrade Activate", "mbus.apl.app_block.vif_upgrade_activate", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_vif_upgrade_cancel,
            { "Upgrade Cancel", "mbus.apl.app_block.vif_upgrade_cancel", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_vif_upgrade_block_status,
            { "Upgrade Block Status", "mbus.apl.app_block.vif_upgrade_block_status", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_ita_segment_length,
            { "Length", "mbus.apl.ita.segment.length", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_ita_segment_id,
            { "ID", "mbus.apl.ita.segment.id", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_ita_segment_function_field,
            { "Function Field", "mbus.apl.ita.segment.function_field", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mbus_ita_function_field_names_ext,
              0x00, NULL, HFILL } },
        { &hf_mbus_ita_segment_sub_function_field,
            { "Sub Function Field", "mbus.apl.ita.segment.sub_function_field", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_ita_segment_payload,
            { "Payload", "mbus.apl.ita.segment.payload", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } }
    };

    /* MBus subtrees */
    int *ett[MBUS_NUM_TOTAL_ETT];
    ett[0] = &ett_mbus_apl;
    ett[1] = &ett_mbus_dif;
    ett[2] = &ett_mbus_dife;
    ett[3] = &ett_mbus_vif;
    ett[4] = &ett_mbus_vife;

    size_t j = MBUS_NUM_INDIVIDUAL_ETT;

    /* Initialize mbus application block subtrees */
    for (size_t i = 0; i < MBUS_NUM_MBUS_APP_BLOCK_ETT; i++, j++) {
        ett[j] = &ett_mbus_long_frame_app_block[i];
    }

    proto_mbus_apl = proto_register_protocol("MBus APL", "MBus APL", MBUS_PROTOABBREV_APL);
    proto_register_field_array(proto_mbus_apl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    mbus_apl_handle = register_dissector(MBUS_PROTOABBREV_APL, dissect_mbus_apl, proto_mbus_apl);

    heur_subdissector_list = register_heur_dissector_list_with_description("mbus", "MBus payload fallback", proto_mbus_apl);
}

void
proto_reg_handoff_mbus_apl(void)
{
    dtls_handle = find_dissector("dtls");

    heur_dissector_add("dtls", dissect_mbus_apl_heur_dtls, "MBus over DTLS", "mbus_dtls", proto_mbus_apl, HEURISTIC_ENABLE);
}

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
