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

#define dsmr6_attribute_names_VALUE_STRING_LIST(XXX) \
    XXX(DSMR6_ATTRIBUTE_ID_HARDWARE_LR_VERSION,             1, "Hardware LR Version") \
    XXX(DSMR6_ATTRIBUTE_ID_BOOTLOADER_LR_VERSION,           2, "Bootloader LR Version") \
    XXX(DSMR6_ATTRIBUTE_ID_LR_VERSION,                      3, "LR Version") \
    XXX(DSMR6_ATTRIBUTE_ID_HARDWARE_NLR_VERSION,            10, "Hardware NLR Version") \
    XXX(DSMR6_ATTRIBUTE_ID_BOOTLOADER_NLR_VERSION,          11, "Bootloader NLR Version") \
    XXX(DSMR6_ATTRIBUTE_ID_NLR_VERSION,                     12, "NLR Version") \
    XXX(DSMR6_ATTRIBUTE_ID_COMMUNICATION_MODULE_VERSION,    13, "Communication Module Version") \
    XXX(DSMR6_ATTRIBUTE_ID_ADMINISTRATIVE_STATUS,           20, "Administrative Status") \
    XXX(DSMR6_ATTRIBUTE_ID_X0_STATUS,                       21, "X0 Status") \
    XXX(DSMR6_ATTRIBUTE_ID_TEST_MODE_STATUS,                22, "Test Mode Status") \
    XXX(DSMR6_ATTRIBUTE_ID_TEST_MODE_DURATION,              23, "Test Mode Duration") \
    XXX(DSMR6_ATTRIBUTE_ID_TEST_MODE_BACKLIGHT_DURATION,    24, "Test Mode Backlight Duration") \
    XXX(DSMR6_ATTRIBUTE_ID_AVERAGE_COMPUTATION_USED,        30, "Average Computation Used") \
    XXX(DSMR6_ATTRIBUTE_ID_DATA_STORAGE_USED,               31, "Data Storage Used") \
    XXX(DSMR6_ATTRIBUTE_ID_MEMORY_USED,                     32, "Memory Used") \
    XXX(DSMR6_ATTRIBUTE_ID_UPTIME,                          33, "Uptime") \
    XXX(DSMR6_ATTRIBUTE_ID_BATTERY_DAYS_LEFT,               34, "Battery Days Left") \
    XXX(DSMR6_ATTRIBUTE_ID_AVERAGE_COMPUTATION_INTERVAL,    40, "Average Computation Interval") \
    XXX(DSMR6_ATTRIBUTE_ID_AMBIENT_TEMPERATURE,             50, "Ambient Temperature") \
    XXX(DSMR6_ATTRIBUTE_ID_GAS_TEMPERATURE,                 51, "Gas Temperature") \
    XXX(DSMR6_ATTRIBUTE_ID_GAS_FLOW,                        52, "Gas Flow") \
    XXX(DSMR6_ATTRIBUTE_ID_METER_INDEX_VALUE,               70, "Meter Index Value") \
    XXX(DSMR6_ATTRIBUTE_ID_BACKLIGHT_DURATION,              80, "Backlight Duration") \
    XXX(DSMR6_ATTRIBUTE_ID_EQUIPMENT_IDENTIFIER,            110, "Equipment Identifier") \
    XXX(DSMR6_ATTRIBUTE_ID_GATEWAY_EQUIPMENT_IDENTIFIER,    111, "Gateway Equipment Identifier") \
    XXX(DSMR6_ATTRIBUTE_ID_EVENT_BYTE,                      120, "Event Byte") \
    XXX(DSMR6_ATTRIBUTE_ID_FREQUENT_ACCESS_CYCLE,           150, "Frequent Access Cycle") \
    XXX(DSMR6_ATTRIBUTE_ID_ORPHAN_TIMEOUT_PERIOD,           151, "Orphan Timeout Period") \
    XXX(DSMR6_ATTRIBUTE_ID_CERTIFICATE_EXPIRATION_WARNING,  160, "Certificate Expiration Warning Period")

VALUE_STRING_ENUM(dsmr6_attribute_names);
VALUE_STRING_ARRAY(dsmr6_attribute_names);
static value_string_ext dsmr6_attribute_names_ext = VALUE_STRING_EXT_INIT(dsmr6_attribute_names);

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
static int hf_dsmr6_attribute_hw_lr_version;
static int hf_dsmr6_attribute_bootloader_lr_version;
static int hf_dsmr6_attribute_lr_version;
static int hf_dsmr6_attribute_hw_nlr_version;
static int hf_dsmr6_attribute_bootloader_nlr_version;
static int hf_dsmr6_attribute_nlr_version;
static int hf_dsmr6_attribute_communication_module_version;
static int hf_dsmr6_attribute_administrative_status;
static int hf_dsmr6_attribute_x0_status;
static int hf_dsmr6_attribute_test_mode_status;
static int hf_dsmr6_attribute_test_mode_duration;
static int hf_dsmr6_attribute_test_mode_backlight_duration;
static int hf_dsmr6_attribute_average_computation_used;
static int hf_dsmr6_attribute_data_storage_used;
static int hf_dsmr6_attribute_memory_used;
static int hf_dsmr6_attribute_uptime;
static int hf_dsmr6_attribute_battery_days_left;
static int hf_dsmr6_attribute_average_computation_interval;
static int hf_dsmr6_attribute_ambient_temperature;
static int hf_dsmr6_attribute_gas_temperature;
static int hf_dsmr6_attribute_gas_flow;
static int hf_dsmr6_attribute_meter_index_value;
static int hf_dsmr6_attribute_backlight_duration;
static int hf_dsmr6_attribute_equipment_identifier;
static int hf_dsmr6_attribute_gateway_equipment_identifier;
static int hf_dsmr6_attribute_event_byte;
static int hf_dsmr6_attribute_frequent_access_cycle;
static int hf_dsmr6_attribute_orphan_timeout_period;
static int hf_dsmr6_attribute_certificate_expiration_warning;

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

        uint8_t attribute_id = tvb_get_uint8(tvb, *offset);
        proto_tree_add_item(attribute_tree, hf_dsmr6_read_attributes_response_attribute_id, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        uint8_t status = tvb_get_uint8(tvb, *offset);
        proto_tree_add_item(attribute_tree, hf_dsmr6_read_attributes_response_status, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        if (status != DSMR6_STATUS_SUCCESS) {
            continue;
        }

        proto_tree_add_item(attribute_tree, hf_dsmr6_read_attributes_response_data_type, tvb, *offset, 1, ENC_NA);
        *offset += 1;

        int length = 0;
        switch (attribute_id) {
            case DSMR6_ATTRIBUTE_ID_HARDWARE_LR_VERSION:
                proto_tree_add_item_ret_length(attribute_tree, hf_dsmr6_attribute_hw_lr_version, tvb, *offset, 1, ENC_NA, &length);
                *offset += length;
                break;
            case DSMR6_ATTRIBUTE_ID_BOOTLOADER_LR_VERSION:
                proto_tree_add_item_ret_length(attribute_tree, hf_dsmr6_attribute_bootloader_lr_version, tvb, *offset, 1, ENC_NA, &length);
                *offset += length;
                break;
            case DSMR6_ATTRIBUTE_ID_LR_VERSION:
                proto_tree_add_item_ret_length(attribute_tree, hf_dsmr6_attribute_lr_version, tvb, *offset, 1, ENC_NA, &length);
                *offset += length;
                break;
            case DSMR6_ATTRIBUTE_ID_HARDWARE_NLR_VERSION:
                proto_tree_add_item_ret_length(attribute_tree, hf_dsmr6_attribute_hw_nlr_version, tvb, *offset, 1, ENC_NA, &length);
                *offset += length;
                break;
            case DSMR6_ATTRIBUTE_ID_BOOTLOADER_NLR_VERSION:
                proto_tree_add_item_ret_length(attribute_tree, hf_dsmr6_attribute_bootloader_nlr_version, tvb, *offset, 1, ENC_NA, &length);
                *offset += length;
                break;
            case DSMR6_ATTRIBUTE_ID_NLR_VERSION:
                proto_tree_add_item_ret_length(attribute_tree, hf_dsmr6_attribute_nlr_version, tvb, *offset, 1, ENC_NA, &length);
                *offset += length;
                break;
            case DSMR6_ATTRIBUTE_ID_COMMUNICATION_MODULE_VERSION:
                proto_tree_add_item_ret_length(attribute_tree, hf_dsmr6_attribute_communication_module_version, tvb, *offset, 1, ENC_NA, &length);
                *offset += length;
                break;
            case DSMR6_ATTRIBUTE_ID_ADMINISTRATIVE_STATUS:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_administrative_status, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
            case DSMR6_ATTRIBUTE_ID_X0_STATUS:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_x0_status, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
            case DSMR6_ATTRIBUTE_ID_TEST_MODE_STATUS:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_test_mode_status, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
            case DSMR6_ATTRIBUTE_ID_TEST_MODE_DURATION:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_test_mode_duration, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
                break;
            case DSMR6_ATTRIBUTE_ID_TEST_MODE_BACKLIGHT_DURATION:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_test_mode_backlight_duration, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
                break;
            case DSMR6_ATTRIBUTE_ID_AVERAGE_COMPUTATION_USED:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_average_computation_used, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;
            case DSMR6_ATTRIBUTE_ID_DATA_STORAGE_USED:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_data_storage_used, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;
            case DSMR6_ATTRIBUTE_ID_MEMORY_USED:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_memory_used, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;
            case DSMR6_ATTRIBUTE_ID_UPTIME:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_uptime, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;
            case DSMR6_ATTRIBUTE_ID_BATTERY_DAYS_LEFT:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_battery_days_left, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;
            case DSMR6_ATTRIBUTE_ID_AVERAGE_COMPUTATION_INTERVAL:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_average_computation_interval, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
                break;
            case DSMR6_ATTRIBUTE_ID_AMBIENT_TEMPERATURE:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_ambient_temperature, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
                break;
            case DSMR6_ATTRIBUTE_ID_GAS_TEMPERATURE:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_gas_temperature, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
                break;
            case DSMR6_ATTRIBUTE_ID_GAS_FLOW:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_gas_flow, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
                break;
            case DSMR6_ATTRIBUTE_ID_METER_INDEX_VALUE:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_meter_index_value, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
                *offset += 4;
                break;
            case DSMR6_ATTRIBUTE_ID_BACKLIGHT_DURATION:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_backlight_duration, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
                break;
            case DSMR6_ATTRIBUTE_ID_EQUIPMENT_IDENTIFIER:
                proto_tree_add_item_ret_length(attribute_tree, hf_dsmr6_attribute_equipment_identifier, tvb, *offset, 1, ENC_NA, &length);
                *offset += length;
                break;
            case DSMR6_ATTRIBUTE_ID_GATEWAY_EQUIPMENT_IDENTIFIER:
                proto_tree_add_item_ret_length(attribute_tree, hf_dsmr6_attribute_gateway_equipment_identifier, tvb, *offset, 1, ENC_NA, &length);
                *offset += length;
                break;
            case DSMR6_ATTRIBUTE_ID_EVENT_BYTE:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_event_byte, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
            case DSMR6_ATTRIBUTE_ID_FREQUENT_ACCESS_CYCLE:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_frequent_access_cycle, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
                break;
            case DSMR6_ATTRIBUTE_ID_ORPHAN_TIMEOUT_PERIOD:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_orphan_timeout_period, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
                *offset += 2;
                break;
            case DSMR6_ATTRIBUTE_ID_CERTIFICATE_EXPIRATION_WARNING:
                proto_tree_add_item(attribute_tree, hf_dsmr6_attribute_certificate_expiration_warning, tvb, *offset, 1, ENC_NA);
                *offset += 1;
                break;
            default:
                // Unknown attribute ID, skip the value based on data type
                break;
        }
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
            { "Attribute ID", "dsmr6.read_attributes.attribute_id", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &dsmr6_attribute_names_ext,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_response_number_of_attributes,
            { "Number of Attributes", "dsmr6.read_attributes_response.number_of_attributes", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_response_attribute_id,
            { "Attribute ID", "dsmr6.read_attributes_response.attribute_id", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &dsmr6_attribute_names_ext,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_response_status,
            { "Attribute Status", "dsmr6.read_attributes_response.status", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &dsmr6_status_names_ext,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_read_attributes_response_data_type,
            { "Attribute Data Type", "dsmr6.read_attributes_response.data_type", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_hw_lr_version,
            { "Hardware LR Version", "dsmr6.read_attributes_response.attr_hw_lr_version", FT_UINT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_bootloader_lr_version,
            { "Bootloader LR Version", "dsmr6.read_attributes_response.attr_bootloader_lr_version", FT_UINT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_lr_version,
            { "LR Version", "dsmr6.read_attributes_response.attr_lr_version", FT_UINT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_hw_nlr_version,
            { "Hardware NLR Version", "dsmr6.read_attributes_response.attr_hw_nlr_version", FT_UINT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_bootloader_nlr_version,
            { "Bootloader NLR Version", "dsmr6.read_attributes_response.attr_bootloader_nlr_version", FT_UINT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_nlr_version,
            { "NLR Version", "dsmr6.read_attributes_response.attr_nlr_version", FT_UINT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_communication_module_version,
            { "Communication Module Version", "dsmr6.read_attributes_response.attr_communication_module_version", FT_UINT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_administrative_status,
            { "Administrative Status", "dsmr6.read_attributes_response.attr_administrative_status", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_x0_status,
            { "X0 Status", "dsmr6.read_attributes_response.attr_x0_status", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_test_mode_status,
            { "Test Mode Status", "dsmr6.read_attributes_response.attr_test_mode_status", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_test_mode_duration,
            { "Test Mode Duration", "dsmr6.read_attributes_response.attr_test_mode_duration", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_test_mode_backlight_duration,
            { "Test Mode Backlight Duration", "dsmr6.read_attributes_response.attr_test_mode_backlight_duration", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_average_computation_used,
            { "Average Computation Used", "dsmr6.read_attributes_response.attr_average_computation_used", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_data_storage_used,
            { "Data Storage Used", "dsmr6.read_attributes_response.attr_data_storage_used", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_memory_used,
            { "Memory Used", "dsmr6.read_attributes_response.attr_memory_used", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_uptime,
            { "Uptime", "dsmr6.read_attributes_response.attr_uptime", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_battery_days_left,
            { "Battery Days Left", "dsmr6.read_attributes_response.attr_battery_days_left", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_average_computation_interval,
            { "Average Computation Interval", "dsmr6.read_attributes_response.attr_average_computation_interval", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_ambient_temperature,
            { "Ambient Temperature", "dsmr6.read_attributes_response.attr_ambient_temperature", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_gas_temperature,
            { "Gas Temperature", "dsmr6.read_attributes_response.attr_gas_temperature", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_gas_flow,
            { "Gas Flow", "dsmr6.read_attributes_response.attr_gas_flow", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_meter_index_value,
            { "Meter Index Value", "dsmr6.read_attributes_response.attr_meter_index_value", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_backlight_duration,
            { "Backlight Duration", "dsmr6.read_attributes_response.attr_backlight_duration", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_equipment_identifier,
            { "Equipment Identifier", "dsmr6.read_attributes_response.attr_equipment_identifier", FT_UINT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_gateway_equipment_identifier,
            { "Gateway Equipment Identifier", "dsmr6.read_attributes_response.attr_gateway_equipment_identifier", FT_UINT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_event_byte,
            { "Event Byte", "dsmr6.read_attributes_response.attr_event_byte", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_frequent_access_cycle,
            { "Frequent Access Cycle", "dsmr6.read_attributes_response.attr_frequent_access_cycle", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_orphan_timeout_period,
            { "Orphan Timeout Period", "dsmr6.read_attributes_response.attr_orphan_timeout_period", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_dsmr6_attribute_certificate_expiration_warning,
            { "Certificate Expiration Warning", "dsmr6.read_attributes_response.attr_certificate_expiration_warning", FT_UINT8, BASE_DEC, NULL,
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
