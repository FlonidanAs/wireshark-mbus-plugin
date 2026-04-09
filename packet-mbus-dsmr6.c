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

/* MBus Proprietary Commands */
#define mbus_proprietary_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX(MBUS_PROPRIETARY_COMMAND_DSMR6,                           0x60, "DSMR6")

VALUE_STRING_ENUM(mbus_proprietary_cmd_names);
VALUE_STRING_ARRAY(mbus_proprietary_cmd_names);
static value_string_ext mbus_proprietary_cmd_names_ext = VALUE_STRING_EXT_INIT(mbus_proprietary_cmd_names);

#define dsmr6_message_codes_VALUE_STRING_LIST(XXX) \
    XXX(DSMR6_MESSAGE_CODE_BILLING_PUSH_VC,                       0x01, "Billing Push (Vc)") \
    XXX(DSMR6_MESSAGE_CODE_BILLING_PUSH_VB,                       0x02, "Billing Push (Vb)") \
    XXX(DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VC,                      0x03, "Periodic Push (Vc)") \
    XXX(DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VB,                      0x04, "Periodic Push (Vb)") \
    XXX(DSMR6_MESSAGE_CODE_EVENT_PUSH,                            0x05, "Event Push")

VALUE_STRING_ENUM(dsmr6_message_codes);
VALUE_STRING_ARRAY(dsmr6_message_codes);
static value_string_ext dsmr6_message_codes_ext = VALUE_STRING_EXT_INIT(dsmr6_message_codes);

/*************************/
/* Function Declarations */
/*************************/
void proto_register_mbus_dsmr6(void);
void proto_reg_handoff_mbus_dsmr6(void);

/*************************/
/** Global Variables    **/
/*************************/
/* Dissector Handles. */
static dissector_handle_t mbus_dsmr6_handle;

/* Initialize the protocol and registered fields */
static int proto_mbus_dsmr6;

static int hf_mbus_man_code;
static int hf_mbus_dsmr6_message_code;
static int hf_mbus_dsmr6_message_length;
static int hf_mbus_dsmr6_date_time;
static int hf_mbus_dsmr6_equipment_id;
static int hf_mbus_dsmr6_volume;
static int hf_mbus_dsmr6_amr_status_byte;
static int hf_mbus_dsmr6_signature;
static int hf_mbus_dsmr6_temperature;
static int hf_mbus_dsmr6_status_byte;
static int hf_mbus_dsmr6_event_time;
static int hf_mbus_dsmr6_event_log;
static int hf_mbus_dsmr6_event_code;

static int ett_mbus_dsmr6;

static void dissect_billing_push(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_mbus_dsmr6_date_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbus_dsmr6_equipment_id, tvb, *offset, 17, ENC_LITTLE_ENDIAN);
    *offset += 17;
    proto_tree_add_item(tree, hf_mbus_dsmr6_volume, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbus_dsmr6_amr_status_byte, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_mbus_dsmr6_signature, tvb, *offset, 64, ENC_NA);
    *offset += 64;
    proto_tree_add_item(tree, hf_mbus_dsmr6_temperature, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_mbus_dsmr6_status_byte, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_mbus_dsmr6_event_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbus_dsmr6_event_log, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_mbus_dsmr6_event_code, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static void dissect_periodic_push(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_mbus_dsmr6_date_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbus_dsmr6_volume, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbus_dsmr6_temperature, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;
    proto_tree_add_item(tree, hf_mbus_dsmr6_status_byte, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    proto_tree_add_item(tree, hf_mbus_dsmr6_event_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL | ENC_LITTLE_ENDIAN);
    *offset += 4;
    proto_tree_add_item(tree, hf_mbus_dsmr6_event_code, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static void
dissect_mbus_dsmr6_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int* offset)
{
    uint8_t message_code = tvb_get_uint8(tvb, *offset);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(message_code, dsmr6_message_codes, "Unknown Cmd"));
    proto_tree_add_item(tree, hf_mbus_dsmr6_message_code, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    // uint16_t message_length = tvb_get_uint16(tvb, *offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_mbus_dsmr6_message_length, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
    *offset += 2;

    switch (message_code) {
        case DSMR6_MESSAGE_CODE_BILLING_PUSH_VC:
        case DSMR6_MESSAGE_CODE_BILLING_PUSH_VB:
            dissect_billing_push(tvb, pinfo, tree, offset);
            break;
        case DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VC:
        case DSMR6_MESSAGE_CODE_PERIODIC_PUSH_VB:
            dissect_periodic_push(tvb, pinfo, tree, offset);
            break;
        case DSMR6_MESSAGE_CODE_EVENT_PUSH:
            break;
        default:
            break;
    }
}

static bool check_dsmr6_command(tvbuff_t *tvb)
{
    int offset = 0;

    if (tvb_reported_length(tvb) < 1) {
        return false; // Not enough data for DSMR6 command
    }

    uint8_t man_code = tvb_get_uint8(tvb, offset);
    if (man_code != MBUS_PROPRIETARY_COMMAND_DSMR6) {
        return false;
    }

    // TODO Check further fields if necessary (DSMR6 header)

    return true;
}

static int
dissect_mbus_dsmr6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (!check_dsmr6_command(tvb)) {
        return 0;
    }

    proto_tree* mbus_flo_tree;
    proto_item* proto_root;
    int offset = 0;

    /* Create the protocol tree */
    proto_root = proto_tree_add_protocol_format(tree, proto_mbus_dsmr6, tvb, offset, tvb_captured_length(tvb), "DSMR6");
    mbus_flo_tree = proto_item_add_subtree(proto_root, ett_mbus_dsmr6);

    uint8_t man_code = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(mbus_flo_tree, hf_mbus_man_code, tvb, offset, 1, ENC_NA);
    offset += 1;

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s", val_to_str_const(man_code, mbus_proprietary_cmd_names, "Unknown Cmd"));

    switch (man_code) {
        case MBUS_PROPRIETARY_COMMAND_DSMR6:
            dissect_mbus_dsmr6_command(tvb, pinfo, mbus_flo_tree, &offset);
            break;
        default:
            break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_mbus_dsmr6(void)
{
    static hf_register_info hf[] = {
        { &hf_mbus_man_code,
            { "Manufacturer Code", "mbus_dsmr6.man_code", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mbus_proprietary_cmd_names_ext,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_message_code,
            { "Message Code", "mbus_dsmr6.message_code", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &dsmr6_message_codes_ext,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_message_length,
            { "Message Length", "mbus_dsmr6.message_length", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_date_time,
            { "Date Time", "mbus_dsmr6.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
              0x00, NULL, HFILL} },
        { &hf_mbus_dsmr6_equipment_id,
            { "Equipment ID", "mbus_dsmr6.equipment_id", FT_STRING, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_volume,
            { "Volume", "mbus_dsmr6.volume", FT_UINT32, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_amr_status_byte,
            { "AMR Status Byte", "mbus_dsmr6.amr_status_byte", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_signature,
            { "Signature", "mbus_dsmr6.signature", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_temperature,
            { "Temperature", "mbus_dsmr6.temperature", FT_UINT16, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_status_byte,
            { "Status Byte", "mbus_dsmr6.status_byte", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_event_time,
            { "Event Time", "mbus_dsmr6.event_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL,
              0x00, NULL, HFILL} },
        { &hf_mbus_dsmr6_event_log,
            { "Event Log", "mbus_dsmr6.event_log", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_dsmr6_event_code,
            { "Event Code", "mbus_dsmr6.event_code", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } }
    };

    /* MBus subtrees */
    int *ett[] = {
        &ett_mbus_dsmr6
    };

    proto_mbus_dsmr6 = proto_register_protocol("MBus DSMR6", "MBus DSMR6", "mbus_dsmr6");
    proto_register_field_array(proto_mbus_dsmr6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    mbus_dsmr6_handle = register_dissector("mbus_dsmr6", dissect_mbus_dsmr6, proto_mbus_dsmr6);
}

static bool
dissect_dsmr6_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (dissect_mbus_dsmr6(tvb, pinfo, tree, false) == 0) {
        // Not a valid MBus DSMR6 packet
        return false;
    }
    return true;
}

void
proto_reg_handoff_mbus_dsmr6(void)
{
    heur_dissector_add("dtls", dissect_dsmr6_heur, "DSMR6 over DTLS", "dsmr6_dtls", proto_mbus_dsmr6, HEURISTIC_ENABLE);
    heur_dissector_add("mbus", dissect_dsmr6_heur, "DSMR6 over MBus", "dsmr6_mbus", proto_mbus_dsmr6, HEURISTIC_ENABLE);
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
