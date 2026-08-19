/* packet-mbus-dsmr6.c
 * Routines for MBus DSMR6 dissection.
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
#include <stdint.h>

#define dsmr6_protocol_id_names_VALUE_STRING_LIST(XXX) \
    XXX(DSMR6_PROTOCOL_ID, 0x60, "DSMR6")

VALUE_STRING_ENUM(dsmr6_protocol_id_names);
VALUE_STRING_ARRAY(dsmr6_protocol_id_names);
static value_string_ext dsmr6_protocol_id_names_ext = VALUE_STRING_EXT_INIT(dsmr6_protocol_id_names);

#define dsmr6_message_codes_VALUE_STRING_LIST(XXX) \
    XXX(DSMR6_MESSAGE_CODE_DEFAULT_RESPONSE,                      0, "Default Response") \
    XXX(DSMR6_MESSAGE_CODE_BILLING_PUSH_VC_NO_SIGNATURE,          1, "Billing Push Vc (No Signature)") \
    XXX(DSMR6_MESSAGE_CODE_BILLING_PUSH_VC,                       2, "Billing Push Vc") \
    XXX(DSMR6_MESSAGE_CODE_BILLING_PUSH_VB_NO_SIGNATURE,          3, "Billing Push Vb (No Signature)") \
    XXX(DSMR6_MESSAGE_CODE_BILLING_PUSH_VB,                       4, "Billing Push Vb") \
    XXX(DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VC_NO_SIGNATURE,         10, "Periodic Push Vc (No Signature)") \
    XXX(DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VC,                      11, "Periodic Push Vc") \
    XXX(DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VB_NO_SIGNATURE,         12, "Periodic Push Vb (No Signature)") \
    XXX(DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VB,                      13, "Periodic Push Vb") \
    XXX(DSMR6_MESSAGE_CODE_EVENT_PUSH,                            20, "Event Push") \
    XXX(DSMR6_MESSAGE_CODE_CONFIGURE_BILLING_INTERVAL,            30, "Configure Billing Interval") \
    XXX(DSMR6_MESSAGE_CODE_CONFIGURE_BILLING_INTERVAL_RESPONSE,   31, "Configure Billing Interval Response") \
    XXX(DSMR6_MESSAGE_CODE_CONFIGURE_PERIODIC_INTERVAL,           40, "Configure Periodic Interval") \
    XXX(DSMR6_MESSAGE_CODE_CONFIGURE_PERIODIC_INTERVAL_RESPONSE,  41, "Configure Periodic Interval Response") \
    XXX(DSMR6_MESSAGE_CODE_READ_BILLING_LOG,                      50, "Read Billing Log") \
    XXX(DSMR6_MESSAGE_CODE_READ_BILLING_LOG_RESPONSE,             51, "Read Billing Log Response") \
    XXX(DSMR6_MESSAGE_CODE_CLEAR_BILLING_LOG,                     52, "Clear Billing Log") \
    XXX(DSMR6_MESSAGE_CODE_CLEAR_BILLING_LOG_RESPONSE,            53, "Clear Billing Log Response") \
    XXX(DSMR6_MESSAGE_CODE_READ_EVENT_LOG,                        60, "Read Event Log") \
    XXX(DSMR6_MESSAGE_CODE_READ_EVENT_LOG_RESPONSE,               61, "Read Event Log Response") \
    XXX(DSMR6_MESSAGE_CODE_CLEAR_EVENT_LOG,                       62, "Clear Event Log") \
    XXX(DSMR6_MESSAGE_CODE_CLEAR_EVENT_LOG_RESPONSE,              63, "Clear Event Log Response") \
    XXX(DSMR6_MESSAGE_CODE_READ_ATTRIBUTES,                       70, "Read Attributes") \
    XXX(DSMR6_MESSAGE_CODE_READ_ATTRIBUTES_RESPONSE,              71, "Read Attributes Response") \
    XXX(DSMR6_MESSAGE_CODE_WRITE_ATTRIBUTES,                      80, "Write Attributes") \
    XXX(DSMR6_MESSAGE_CODE_WRITE_ATTRIBUTES_RESPONSE,             81, "Write Attributes Response")

VALUE_STRING_ENUM(dsmr6_message_codes);
VALUE_STRING_ARRAY(dsmr6_message_codes);
static value_string_ext dsmr6_message_codes_ext = VALUE_STRING_EXT_INIT(dsmr6_message_codes);

#define dsmr6_status_names_VALUE_STRING_LIST(XXX) \
    XXX(DSMR6_STATUS_SUCCESS,               0, "Success") \
    XXX(DSMR6_STATUS_FAILURE,               1, "Failure") \
    XXX(DSMR6_STATUS_UNSUPPORTED_ATTRIBUTE, 2, "Unsupported Attribute") \
    XXX(DSMR6_STATUS_INVALID_VALUE,         3, "Invalid Value") \
    XXX(DSMR6_STATUS_READ_ONLY,             4, "Read Only") \
    XXX(DSMR6_STATUS_WRITE_ONLY,            5, "Write Only") \
    XXX(DSMR6_STATUS_INVALID_DATA_TYPE,     6, "Invalid Data Type") \
    XXX(DSMR6_STATUS_UNSUPPORTED_COMMAND,   7, "Unsupported Command") \

VALUE_STRING_ENUM(dsmr6_status_names);
VALUE_STRING_ARRAY(dsmr6_status_names);
static value_string_ext dsmr6_status_names_ext = VALUE_STRING_EXT_INIT(dsmr6_status_names);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_dsmr6(void);
void proto_reg_handoff_dsmr6(void);

/*************************/
/** Global Variables    **/
/*************************/
/* Dissector Handles. */
static dissector_handle_t dsmr6_handle;

/* Initialize the protocol and registered fields */
static int proto_dsmr6;

static int hf_dsmr6_protocol_id;
static int hf_dsmr6_message_code;
static int hf_dsmr6_message_length;
static int hf_dsmr6_date_time;
static int hf_dsmr6_equipment_id;
static int hf_dsmr6_volume;
static int hf_dsmr6_amr_status_byte;
static int hf_dsmr6_signature_length;
static int hf_dsmr6_signature;
static int hf_dsmr6_temperature;
static int hf_dsmr6_status_byte;
static int hf_dsmr6_default_response_cmd_id;
static int hf_dsmr6_default_response_status;
static int hf_dsmr6_billing_log_start_time;
static int hf_dsmr6_billing_log_end_time;
static int hf_dsmr6_billing_log_id;
static int hf_dsmr6_billing_log_number_of_entries;
static int hf_dsmr6_clear_billing_log_logs;
static int hf_dsmr6_event_push_time;
static int hf_dsmr6_event_push_log;
static int hf_dsmr6_event_push_code;
static int hf_dsmr6_event_push_data;
static int hf_dsmr6_event_push_status_byte;
static int hf_dsmr6_read_attributes_number_of_attributes;
static int hf_dsmr6_read_attributes_attribute_id;
static int hf_dsmr6_read_attributes_response_number_of_attributes;
static int hf_dsmr6_read_attributes_response_attribute_id;
static int hf_dsmr6_read_attributes_response_status;
static int hf_dsmr6_read_attributes_response_data_type;
static int hf_dsmr6_read_attributes_response_value;

static int ett_dsmr6;
static int ett_dsmr6_header;
static int ett_dsmr6_payload;
static int ett_dsmr6_billing_log_entries;
static int ett_dsmr6_read_attributes_response_entries;

static void dissect_default_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_dsmr6_default_response_cmd_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_dsmr6_default_response_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static void dissect_billing_push(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_dsmr6_date_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_dsmr6_equipment_id, tvb, *offset, 17, ENC_LITTLE_ENDIAN);
    *offset += 17;
    proto_tree_add_item(tree, hf_dsmr6_volume, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_dsmr6_amr_status_byte, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    uint8_t signature_length = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_dsmr6_signature_length, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    if (signature_length > 0) {
        proto_tree_add_item(tree, hf_dsmr6_signature, tvb, *offset, signature_length, ENC_NA);
        *offset += signature_length;
    }
    proto_tree_add_item(tree, hf_dsmr6_temperature, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_dsmr6_status_byte, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static void dissect_periodic_push_no_signature(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_dsmr6_date_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_dsmr6_volume, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_dsmr6_temperature, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_dsmr6_status_byte, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static void dissect_read_billing_log(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_dsmr6_billing_log_start_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_dsmr6_billing_log_end_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_dsmr6_billing_log_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static void dissect_read_billing_log_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_dsmr6_billing_log_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    uint8_t number_of_entries = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_dsmr6_billing_log_number_of_entries, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    for (size_t i = 0; i < number_of_entries; i++) {
        proto_tree* entry_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 0, ett_dsmr6_billing_log_entries, NULL, "Billing Log Entry %zu", i + 1);

        proto_tree_add_item(entry_tree, hf_dsmr6_date_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
        *offset += 4;
        proto_tree_add_item(entry_tree, hf_dsmr6_equipment_id, tvb, *offset, 17, ENC_LITTLE_ENDIAN);
        *offset += 17;
        proto_tree_add_item(entry_tree, hf_dsmr6_volume, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
        *offset += 4;
        proto_tree_add_item(entry_tree, hf_dsmr6_amr_status_byte, tvb, *offset, 1, ENC_NA);
        *offset += 1;
        uint8_t signature_length = tvb_get_uint8(tvb, *offset);
        proto_tree_add_item(entry_tree, hf_dsmr6_signature_length, tvb, *offset, 1, ENC_NA);
        *offset += 1;
        if (signature_length > 0) {
            proto_tree_add_item(entry_tree, hf_dsmr6_signature, tvb, *offset, signature_length, ENC_NA);
            *offset += signature_length;
        }
    }
}

static void dissect_clear_billing_log(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_dsmr6_clear_billing_log_logs, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static void dissect_event_push(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_dsmr6_event_push_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_dsmr6_event_push_log, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_dsmr6_event_push_code, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_dsmr6_event_push_data, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_dsmr6_event_push_status_byte, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static uint8_t get_attribute_value_length(uint8_t data_type)
{
    switch (data_type) {
        case 0x00:
        case 0x10:
            return 1;
        case 0x01:
        case 0x11:
            return 2;
        case 0x02:
        case 0x12:
            return 4;
        case 0x03:
        case 0x13:
            return 8;
        default:
            return 0; // Unknown data type
    }
}

static void dissect_read_attributes(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    uint8_t number_of_attributes = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_dsmr6_read_attributes_number_of_attributes, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    for (size_t i = 0; i < number_of_attributes; i++) {
        proto_tree_add_item(tree, hf_dsmr6_read_attributes_attribute_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;
    }
}

static void dissect_read_attributes_response(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    uint8_t number_of_attributes = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(tree, hf_dsmr6_read_attributes_response_number_of_attributes, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    for (size_t i = 0; i < number_of_attributes; i++) {
        proto_tree* attribute_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 0, ett_dsmr6_read_attributes_response_entries, NULL, "Attribute %zu", i + 1);

        proto_tree_add_item(attribute_tree, hf_dsmr6_read_attributes_response_attribute_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        uint8_t status = tvb_get_uint8(tvb, *offset);
        proto_tree_add_item(attribute_tree, hf_dsmr6_read_attributes_response_status, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        if (status != DSMR6_STATUS_SUCCESS) {
            continue;
        }

        uint8_t data_type = tvb_get_uint8(tvb, *offset);
        proto_tree_add_item(attribute_tree, hf_dsmr6_read_attributes_response_data_type, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        uint8_t value_length = get_attribute_value_length(data_type);
        proto_tree_add_item(attribute_tree, hf_dsmr6_read_attributes_response_value, tvb, *offset, value_length, ENC_LITTLE_ENDIAN);
        *offset += value_length;
    }
}

static bool check_dsmr6_command(tvbuff_t *tvb)
{
    int offset = 0;

    if (tvb_reported_length(tvb) < 1) {
        return false; // Not enough data for DSMR6 command
    }

    uint8_t protocol_id = tvb_get_uint8(tvb, offset);
    if (protocol_id != DSMR6_PROTOCOL_ID) {
        return false;
    }

    // TODO Check further fields if necessary (DSMR6 header)

    return true;
}

static int
dissect_dsmr6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (!check_dsmr6_command(tvb)) {
        return 0;
    }

    int offset = 0;

    /* Create the protocol tree */
    proto_item* proto_root = proto_tree_add_protocol_format(tree, proto_dsmr6, tvb, offset, tvb_captured_length(tvb), "DSMR6");
    proto_tree* dsmr6_tree = proto_item_add_subtree(proto_root, ett_dsmr6);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSMR6");

    /* Header */
    uint8_t message_code = tvb_get_uint8(tvb, offset + 1); // Message code is at offset 1 in the header
    const char* message_code_str = val_to_str_const(message_code, dsmr6_message_codes, "Unknown Cmd");
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", message_code_str);
    proto_tree* header_tree = proto_tree_add_subtree_format(dsmr6_tree, tvb, offset, 3, ett_dsmr6_header, NULL, "Header: %s", message_code_str);

    proto_tree_add_item(header_tree, hf_dsmr6_protocol_id, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(header_tree, hf_dsmr6_message_code, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(header_tree, hf_dsmr6_message_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Payload */
    int rem_len = tvb_reported_length_remaining(tvb, offset);
    if (rem_len > 0) {
        proto_tree* payload_tree = proto_tree_add_subtree(dsmr6_tree, tvb, offset, rem_len, ett_dsmr6_payload, NULL, "Payload");
        switch (message_code) {
            case DSMR6_MESSAGE_CODE_DEFAULT_RESPONSE:
                dissect_default_response(tvb, pinfo, payload_tree, &offset);
                break;
            case DSMR6_MESSAGE_CODE_BILLING_PUSH_VC:
            case DSMR6_MESSAGE_CODE_BILLING_PUSH_VB:
                dissect_billing_push(tvb, pinfo, payload_tree, &offset);
                break;
            case DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VC_NO_SIGNATURE:
            case DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VB_NO_SIGNATURE:
                dissect_periodic_push_no_signature(tvb, pinfo, payload_tree, &offset);
                break;
            case DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VC:
            case DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VB:
                // Same format as billing push
                dissect_billing_push(tvb, pinfo, payload_tree, &offset);
                break;
            case DSMR6_MESSAGE_CODE_EVENT_PUSH:
                dissect_event_push(tvb, pinfo, payload_tree, &offset);
                break;
            case DSMR6_MESSAGE_CODE_READ_BILLING_LOG:
                dissect_read_billing_log(tvb, pinfo, payload_tree, &offset);
                break;
            case DSMR6_MESSAGE_CODE_READ_BILLING_LOG_RESPONSE:
                dissect_read_billing_log_response(tvb, pinfo, payload_tree, &offset);
                break;
            case DSMR6_MESSAGE_CODE_CLEAR_BILLING_LOG:
                dissect_clear_billing_log(tvb, pinfo, payload_tree, &offset);
                break;
            case DSMR6_MESSAGE_CODE_READ_ATTRIBUTES:
                dissect_read_attributes(tvb, pinfo, payload_tree, &offset);
                break;
            case DSMR6_MESSAGE_CODE_READ_ATTRIBUTES_RESPONSE:
                dissect_read_attributes_response(tvb, pinfo, payload_tree, &offset);
                break;
            default:
                break;
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_dsmr6(void)
{
    static hf_register_info hf[] = {
        { &hf_dsmr6_protocol_id,
            { "Protocol Id", "dsmr6.protocol_id", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &dsmr6_protocol_id_names_ext,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_message_code,
            { "Message Code", "dsmr6.message_code", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &dsmr6_message_codes_ext,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_message_length,
            { "Message Length", "dsmr6.message_length", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_date_time,
            { "Date Time", "dsmr6.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
              0x00, NULL, HFILL} },
        { &hf_dsmr6_equipment_id,
            { "Equipment ID", "dsmr6.equipment_id", FT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_volume,
            { "Volume", "dsmr6.volume", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_amr_status_byte,
            { "AMR Status Byte", "dsmr6.amr_status_byte", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_signature_length,
            { "Signature Length", "dsmr6.signature_length", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_signature,
            { "Signature", "dsmr6.signature", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_temperature,
            { "Temperature", "dsmr6.temperature", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_status_byte,
            { "Status Byte", "dsmr6.status_byte", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_default_response_cmd_id,
            { "Default Response Command Id", "dsmr6.default_response.cmd_id", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &dsmr6_message_codes_ext,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_default_response_status,
            { "Default Response Status", "dsmr6.default_response.status", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &dsmr6_status_names_ext,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_billing_log_start_time,
            { "Billing Log Start Time", "dsmr6.billing_log.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
              0x00, NULL, HFILL} },
        { &hf_dsmr6_billing_log_end_time,
            { "Billing Log End Time", "dsmr6.billing_log.end_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
              0x00, NULL, HFILL} },
        { &hf_dsmr6_billing_log_id,
            { "Billing Log ID", "dsmr6.billing_log.id", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_billing_log_number_of_entries,
            { "Billing Log Number of Entries", "dsmr6.billing_log.number_of_entries", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_clear_billing_log_logs,
            { "Clear Billing Logs", "dsmr6.clear_billing_log.logs", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_event_push_time,
            { "Event Time", "dsmr6.event_push.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
              0x00, NULL, HFILL} },
        { &hf_dsmr6_event_push_log,
            { "Event Log", "dsmr6.event_push.log", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_event_push_code,
            { "Event Code", "dsmr6.event_push.code", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_event_push_data,
            { "Event Data", "dsmr6.event_push.data", FT_UINT32, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_event_push_status_byte,
            { "Event Status Byte", "dsmr6.event_push.status_byte", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_number_of_attributes,
            { "Number of Attributes", "dsmr6.read_attributes.number_of_attributes", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_attribute_id,
            { "Attribute ID", "dsmr6.read_attributes.attribute_id", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_response_attribute_id,
            { "Attribute ID", "dsmr6.read_attributes_response.attribute_id", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_response_status,
            { "Attribute Status", "dsmr6.read_attributes_response.status", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &dsmr6_status_names_ext,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_response_data_type,
            { "Attribute Data Type", "dsmr6.read_attributes_response.data_type", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_response_value,
            { "Attribute Value", "dsmr6.read_attributes_response.value", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
    };

    /* MBus subtrees */
    int *ett[] = {
        &ett_dsmr6,
        &ett_dsmr6_header,
        &ett_dsmr6_payload,
        &ett_dsmr6_billing_log_entries,
        &ett_dsmr6_read_attributes_response_entries,
    };

    proto_dsmr6 = proto_register_protocol("DSMR6", "DSMR6", "dsmr6");
    proto_register_field_array(proto_dsmr6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    dsmr6_handle = register_dissector("dsmr6", dissect_dsmr6, proto_dsmr6);
}

static bool
dissect_dsmr6_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (dissect_dsmr6(tvb, pinfo, tree, false) == 0) {
        // Not a valid MBus DSMR6 packet
        return false;
    }
    return true;
}

void
proto_reg_handoff_dsmr6(void)
{
    heur_dissector_add("dtls", dissect_dsmr6_heur, "DSMR6 over DTLS", "dsmr6_dtls", proto_dsmr6, HEURISTIC_ENABLE);
    heur_dissector_add("mbus", dissect_dsmr6_heur, "DSMR6 over MBus", "dsmr6_mbus", proto_dsmr6, HEURISTIC_ENABLE);
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
