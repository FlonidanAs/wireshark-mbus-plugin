/* packet-mbus.c
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
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-mbus.h"
#include "packet-mbus-common.h"


/*************************/
/* Function Declarations */
/*************************/
void proto_register_mbus(void);
void proto_reg_handoff_mbus(void);

/* Command Dissector Helpers */
static void dissect_mbus_short_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_mbus_long_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/*************************/
/** Global Variables    **/
/*************************/
/* Initialize the protocol and registered fields */
static int proto_mbus;

static int hf_mbus_wakeup;
static int hf_mbus_ack;
static int hf_mbus_short_start;
static int hf_mbus_long_start;
static int hf_mbus_long_len;
static int hf_mbus_cfield;
static int hf_mbus_cfield_primary_to_secondary_function;
static int hf_mbus_cfield_secondary_to_primary_function;
static int hf_mbus_cfield_fcv;
static int hf_mbus_cfield_dfc;
static int hf_mbus_cfield_fcb;
static int hf_mbus_cfield_acd;
static int hf_mbus_cfield_direction;
static int hf_mbus_addr;
static int hf_mbus_crc;
static int hf_mbus_stop;

static int ett_mbus;
static int ett_mbus_link_layer;
static int ett_mbus_cfield;

static expert_field ei_mbus_length_mismatch;

/* Dissector Handles. */
static dissector_handle_t mbus_handle;
static dissector_handle_t mbus_ell_handle;
static dissector_handle_t mbus_afl_handle;
static dissector_handle_t mbus_tpl_handle;

/* CField Function */
static const value_string mbus_cfield_primary_to_seconday_function_names[] = {
    { 0x00, "SND_NKE" },
    { 0x03, "SND_UD" },
    { 0x04, "SND_NR" },
    { 0x06, "SND_IR" },
    { 0x07, "ACC_NR" },
    { 0x08, "ACC_DMD" },
    { 0x0A, "REQ_UD1" },
    { 0x0B, "REQ_UD2" },
    { 0, NULL }
};

/* CField Function */
static const value_string mbus_cfield_secondary_to_primary_function_names[] = {
    { 0x00, "ACK" },
    { 0x06, "CNF_IR" },
    { 0x08, "RSP_UD" },
    { 0, NULL }
};

/* CField flags master to slave */
static int* const cfield_master_to_slave_flags[] = {
    &hf_mbus_cfield_primary_to_secondary_function,
    &hf_mbus_cfield_fcv,
    &hf_mbus_cfield_fcb,
    &hf_mbus_cfield_direction,
    NULL
};

/* CField flags slave to master */
static int* const cfield_slave_to_master_flags[] = {
    &hf_mbus_cfield_secondary_to_primary_function,
    &hf_mbus_cfield_dfc,
    &hf_mbus_cfield_acd,
    &hf_mbus_cfield_direction,
    NULL
};

uint8_t mbus_dissect_cfield(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int* offset)
{
    uint8_t cfield = tvb_get_uint8(tvb, *offset);
    if (cfield & MBUS_C_FIELD_DIR_MASK) {
        proto_tree_add_bitmask(tree, tvb, *offset, hf_mbus_cfield, ett_mbus_cfield, cfield_master_to_slave_flags, ENC_NA);
        for (size_t i = 0; i < array_length(mbus_cfield_primary_to_seconday_function_names); i++) {
            if (mbus_cfield_primary_to_seconday_function_names[i].value == (cfield & MBUS_C_FIELD_FUNC_MASK)) {
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, mbus_cfield_primary_to_seconday_function_names[i].strptr);
                break;
            }
        }
    }
    else {
        proto_tree_add_bitmask(tree, tvb, *offset, hf_mbus_cfield, ett_mbus_cfield, cfield_slave_to_master_flags, ENC_NA);
        for (size_t i = 0; i < array_length(mbus_cfield_secondary_to_primary_function_names); i++) {
            if (mbus_cfield_secondary_to_primary_function_names[i].value == (cfield & MBUS_C_FIELD_FUNC_MASK)) {
                col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, mbus_cfield_secondary_to_primary_function_names[i].strptr);
                break;
            }
        }
    }
    *offset += 1;
    return cfield;
}

/**
 *This function manages mbus short frame
 *
 *@param tvb pointer to buffer containing raw packet
 *@param pinfo pointer to packet info
 *@param tree pointer to data tree Wireshark uses to display packet
*/
static void
dissect_mbus_short_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;

    if (tvb_reported_length_remaining(tvb, offset) != 5) {
        expert_add_info(pinfo, tree, &ei_mbus_length_mismatch);
        return;
    }

    proto_tree_add_item(tree, hf_mbus_short_start, tvb, offset, 1, ENC_NA);
    offset += 1;

    uint8_t cfield = mbus_dissect_cfield(tvb, pinfo, tree, &offset);

    uint8_t address = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mbus_addr, tvb, offset, 1, ENC_NA);
    offset += 1;

    char address_str[5];
    snprintf(address_str, sizeof(address_str), "0x%02x", address);
    mbus_set_address_and_port_info(pinfo, cfield, address_str);

    proto_tree_add_item(tree, hf_mbus_crc, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(tree, hf_mbus_stop, tvb, offset, 1, ENC_NA);
    offset += 1;
} /*dissect_mbus_short_frame*/

/**
 *This function manages mbus long frame
 *
 *@param tvb pointer to buffer containing raw packet
 *@param pinfo pointer to packet info
 *@param tree pointer to data tree Wireshark uses to display packet
*/
static void
dissect_mbus_long_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    mbus_packet_info_t mbus_info;
    memset(&mbus_info, 0, sizeof(mbus_info));
    mbus_info.wireless = false;

    /* Start */
    proto_tree_add_item(tree, hf_mbus_long_start, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mbus_long_len, tvb, offset, 1, ENC_NA);
    if (tvb_reported_length_remaining(tvb, offset) != (tvb_get_uint8(tvb, offset) + 5)) {
        expert_add_info(pinfo, tree, &ei_mbus_length_mismatch);
        return;
    }
    offset += 1;
    proto_tree_add_item(tree, hf_mbus_long_len, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mbus_long_start, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* CField */
    mbus_info.cfield = mbus_dissect_cfield(tvb, pinfo, tree, &offset);

    /* Address */
    mbus_info.wired_info.address = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(tree, hf_mbus_addr, tvb, offset, 1, ENC_NA);
    offset += 1;

    char address_str[5];
    snprintf(address_str, sizeof(address_str), "0x%02x", mbus_info.wired_info.address);
    mbus_set_address_and_port_info(pinfo, mbus_info.cfield, address_str);

    /* Create a new tvb for the next dissector */
    tvbuff_t* new_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset) - 2); // -2 for CRC and 0x16
    offset += tvb_reported_length(new_tvb);

    /* End */
    proto_tree_add_item(tree, hf_mbus_crc, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_mbus_stop, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Call ELL, AFL or TPL dissector. Depends on the CI Field */
    if (tvb_reported_length(new_tvb) > 0) {
        uint8_t cifield = tvb_get_uint8(new_tvb, 0);

        if (mbus_is_ell_ci_field(cifield)) {
            call_dissector_with_data(mbus_ell_handle, new_tvb, pinfo, proto_tree_get_root(tree), &mbus_info);
        }
        else if (mbus_is_afl_ci_field(cifield)) {
            call_dissector_with_data(mbus_afl_handle, new_tvb, pinfo, proto_tree_get_root(tree), &mbus_info);
        }
        else {
            call_dissector_with_data(mbus_tpl_handle, new_tvb, pinfo, proto_tree_get_root(tree), &mbus_info);
        }
    }
} /*dissect_mbus_long_frame*/

static int
dissect_mbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Create the protocol tree */
    proto_item* proto_root = proto_tree_add_protocol_format(tree, proto_mbus, tvb, 0, tvb_captured_length(tvb), "MBus Data Link Layer");
    proto_tree* mbus_tree = proto_item_add_subtree(proto_root, ett_mbus);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MBus");

    switch (tvb_get_uint8(tvb, 0)) {
        case 0x00:
            col_set_str(pinfo->cinfo, COL_INFO, "Wakeup 0x00");
            proto_tree_add_item(mbus_tree, hf_mbus_wakeup, tvb, 0, 1, ENC_NA);
            break;
        case 0x01:
            col_set_str(pinfo->cinfo, COL_INFO, "Wakeup 0x01");
            proto_tree_add_item(mbus_tree, hf_mbus_wakeup, tvb, 0, 1, ENC_NA);
            break;
        case 0xE5:
            col_set_str(pinfo->cinfo, COL_INFO, "Ack");
            proto_tree_add_item(mbus_tree, hf_mbus_ack, tvb, 0, 1, ENC_NA);
            break;
        case 0x10:
            dissect_mbus_short_frame(tvb, pinfo, mbus_tree);
            break;
        case 0x68:
            dissect_mbus_long_frame(tvb, pinfo, mbus_tree);
            break;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_mbus(void)
{
    static hf_register_info hf[] = {
        { &hf_mbus_wakeup,
            { "Wakeup", "mbus.wakeup", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_ack,
            { "Ack", "mbus.ack", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_short_start,
            { "Start", "mbus.short_start", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_long_start,
            { "Start", "mbus.long_start", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_long_len,
            { "Length", "mbus.long_len", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_cfield,
            { "CField", "mbus.cfield", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_cfield_primary_to_secondary_function,
            { "Function", "mbus.cfield.function", FT_UINT8, BASE_HEX, VALS(mbus_cfield_primary_to_seconday_function_names),
              MBUS_C_FIELD_FUNC_MASK, NULL, HFILL } },

        { &hf_mbus_cfield_secondary_to_primary_function,
            { "Function", "mbus.cfield.function", FT_UINT8, BASE_HEX, VALS(mbus_cfield_secondary_to_primary_function_names),
              MBUS_C_FIELD_FUNC_MASK, NULL, HFILL } },

        { &hf_mbus_cfield_fcv,
            { "Frame Count Bit Valid", "mbus.cfield.fcv", FT_BOOLEAN, 8, NULL,
              MBUS_C_FIELD_FCV_DFC_MASK, NULL, HFILL } },

        { &hf_mbus_cfield_dfc,
            { "Data Flow Control", "mbus.cfield.dfc", FT_BOOLEAN, 8, NULL,
              MBUS_C_FIELD_FCV_DFC_MASK, NULL, HFILL } },

        { &hf_mbus_cfield_fcb,
            { "Frame Count Bit", "mbus.cfield.fcb", FT_BOOLEAN, 8, NULL,
              MBUS_C_FIELD_FCB_ACD_MASK, NULL, HFILL } },

        { &hf_mbus_cfield_acd,
            { "Access Demand Bit", "mbus.cfield.acd", FT_BOOLEAN, 8, NULL,
              MBUS_C_FIELD_FCB_ACD_MASK, NULL, HFILL } },

        { &hf_mbus_cfield_direction,
            { "Primary (Primary -> Secondary)", "mbus.cfield.prm", FT_BOOLEAN, 8, NULL,
              MBUS_C_FIELD_DIR_MASK, NULL, HFILL } },

        { &hf_mbus_addr,
            { "Address", "mbus.addr", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_crc,
            { "CRC", "mbus.crc", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_stop,
            { "Stop", "mbus.stop", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
    };

    /* MBus subtrees */
    static int *ett[] = {
        &ett_mbus,
        &ett_mbus_link_layer,
        &ett_mbus_cfield
    };

    static ei_register_info ei[] = {
        { &ei_mbus_length_mismatch, { "mbus.length_mismatch", PI_PROTOCOL, PI_WARN, "Packet length mismatch", EXPFILL }},
    };

    proto_mbus = proto_register_protocol("MBus", "MBus", "mbus");
    proto_register_field_array(proto_mbus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t* expert_mbus = expert_register_protocol(proto_mbus);
    expert_register_field_array(expert_mbus, ei, array_length(ei));

    /* Register dissector */
    mbus_handle = register_dissector(MBUS_PROTOABBREV, dissect_mbus, proto_mbus);
}

void
proto_reg_handoff_mbus(void)
{
    mbus_ell_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_ELL, proto_mbus);
    mbus_afl_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_AFL, proto_mbus);
    mbus_tpl_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_TPL, proto_mbus);
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
