/* packet-wmbus-module.c
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
#include <epan/unit_strings.h>
#include <wsutil/utf8_entities.h>
#include "packet-mbus.h"
#include "packet-wmbus.h"

/*************************/
/* Function Declarations */
/*************************/
void proto_register_wmbus_module(void);
void proto_reg_handoff_wmbus_module(void);

/*************************/
/** Global Variables    **/
/*************************/
/* Dissector Handles. */
static dissector_handle_t wmbus_module_handle;
static dissector_handle_t wmbus_handle;

/* Initialize the protocol and registered fields */
static int proto_wmbus_module;

static int hf_wmbus_module_header_command_id;
static int hf_wmbus_module_header_sequence_number;
static int hf_wmbus_module_header_payload_length;
static int hf_wmbus_module_header_status;
static int hf_wmbus_module_header_mode;
static int hf_wmbus_module_header_format;
static int hf_wmbus_module_header_rssi;
static int hf_wmbus_module_header_timestamp;
static int hf_wmbus_module_header_air_time;

static int ett_wmbus_module;
static int ett_wmbus_module_header;

/**
 *This function manages wmbus module frame
 *
 *@param tvb pointer to buffer containing raw packet
 *@param pinfo pointer to packet info
 *@param tree pointer to data tree Wireshark uses to display packet
 *@param offset pointer to offset from caller
*/
static tvbuff_t*
dissect_wmbus_module_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int *offset, wmbus_message_info_t* wmbus_message_info)
{
    uint32_t data_length;
    proto_tree* header_tree;
    col_set_str(pinfo->cinfo, COL_INFO, "WMBus Module Frame");

    // Header
    header_tree = proto_tree_add_subtree(tree, tvb, *offset, 28, ett_wmbus_module_header, NULL, "Header");

    proto_tree_add_item(header_tree, hf_wmbus_module_header_command_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    proto_tree_add_item(header_tree, hf_wmbus_module_header_sequence_number, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    data_length = tvb_get_uint32(tvb, *offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(header_tree, hf_wmbus_module_header_payload_length, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    proto_tree_add_item(header_tree, hf_wmbus_module_header_status, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    wmbus_message_info->mode = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(header_tree, hf_wmbus_module_header_mode, tvb, *offset, 1, ENC_NA);  //TODO Create enum for mode
    *offset += 1;

    wmbus_message_info->format = tvb_get_uint8(tvb, *offset);
    proto_tree_add_item(header_tree, hf_wmbus_module_header_format, tvb, *offset, 1, ENC_NA); //TODO Create enum for format
    *offset += 1;

    proto_tree_add_item(header_tree, hf_wmbus_module_header_rssi, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_item(header_tree, hf_wmbus_module_header_timestamp, tvb, *offset, 8, ENC_LITTLE_ENDIAN);
    *offset += 8;

    proto_tree_add_item(header_tree, hf_wmbus_module_header_air_time, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    // Data
    if ((data_length - 4u) != tvb_reported_length_remaining(tvb, *offset)) {
        //TODO Expert info
    }

    return tvb_new_subset_remaining(tvb, *offset);
} /*dissect_wmbus_module_frame*/

static int
dissect_wmbus_module(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    proto_tree* mbus_tree;
    proto_tree* proto_root;

    /* Create the protocol tree */
    proto_root = proto_tree_add_protocol_format(tree, proto_wmbus_module, tvb, offset, tvb_captured_length(tvb), "WMBus Module");
    mbus_tree = proto_item_add_subtree(proto_root, ett_wmbus_module);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WMBus Module");

    wmbus_message_info_t wmbus_message_info;
    tvbuff_t* wmbus_tvb = dissect_wmbus_module_frame(tvb, pinfo, mbus_tree, &offset, &wmbus_message_info);
    if (wmbus_tvb != NULL) {
        call_dissector_with_data(wmbus_handle, wmbus_tvb, pinfo, tree, &wmbus_message_info);
    }

    return tvb_captured_length(tvb);
}

// It is not possible to use the variables from unit_strings.c from within a plugin so create our own copy of it
static const unit_name_string my_units_microseconds = { UTF8_MICRO_SIGN "s", NULL };

void
proto_register_wmbus_module(void)
{
    static hf_register_info hf[] = {
        { &hf_wmbus_module_header_command_id,
          { "Command Id", "wmbus_module.header.cmd", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
        { &hf_wmbus_module_header_sequence_number,
          { "Sequence Number", "wmbus_module.header.sequence_number", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
        { &hf_wmbus_module_header_payload_length,
          { "Payload Length", "wmbus_module.header.payload_length", FT_UINT32, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
        { &hf_wmbus_module_header_status,
          { "Status", "wmbus_module.header.status", FT_UINT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
        { &hf_wmbus_module_header_mode,
          { "Message Mode", "wmbus_module.header.mode", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },
        { &hf_wmbus_module_header_format,
          { "Message Format", "wmbus_module.header.format", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },
        { &hf_wmbus_module_header_rssi,
          { "RSSI", "wmbus_module.header.rssi", FT_INT8, BASE_DEC, NULL,
            0x00, NULL, HFILL } },
        { &hf_wmbus_module_header_timestamp,
          { "Timestamp", "wmbus_module.header.timestamp", FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&my_units_microseconds),
            0x00, NULL, HFILL } },
        { &hf_wmbus_module_header_air_time,
          { "Air time", "wmbus_module.header.air_time", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&my_units_microseconds),
            0x00, NULL, HFILL } }
    };

    /* MBus subtrees */
    int* ett[] = {
        &ett_wmbus_module,
        &ett_wmbus_module_header
    };

    proto_wmbus_module = proto_register_protocol("WMBus Module", "WMBus Module", "wmbus_module");
    proto_register_field_array(proto_wmbus_module, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    wmbus_module_handle = register_dissector("wmbus_module", dissect_wmbus_module, proto_wmbus_module);
}

void
proto_reg_handoff_wmbus_module(void)
{
    wmbus_handle = find_dissector_add_dependency(WMBUS_PROTOABBREV, proto_wmbus_module);
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
