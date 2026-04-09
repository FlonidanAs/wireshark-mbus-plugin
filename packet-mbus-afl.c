/* packet-mbus-afl.c
 * Routines for MBus Authentication and Fragmentation Layer (AFL) dissection.
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
#include <epan/reassemble.h>
#include "packet-mbus-common.h"

/*************************/
/* Function Declarations */
/*************************/
void proto_register_mbus_afl(void);
void proto_reg_handoff_mbus_afl(void);

/*************************/
/** Global Variables    **/
/*************************/
/* Initialize the protocol and registered fields */
static int proto_mbus_afl;

static int hf_mbus_afl_cifield;
static int hf_mbus_afl_afll;
static int hf_mbus_afl_fcl;
static int hf_mbus_afl_fcl_fid;
static int hf_mbus_afl_fcl_kip;
static int hf_mbus_afl_fcl_macp;
static int hf_mbus_afl_fcl_mcrp;
static int hf_mbus_afl_fcl_mlp;
static int hf_mbus_afl_fcl_mclp;
static int hf_mbus_afl_fcl_mf;

static int ett_mbus_afl;
static int ett_mbus_afl_fcl;

/* Fragmentation indices. */
static int hf_mbus_afl_fragments;
static int hf_mbus_afl_fragment;
static int hf_mbus_afl_fragment_overlap;
static int hf_mbus_afl_fragment_overlap_conflicts;
static int hf_mbus_afl_fragment_multiple_tails;
static int hf_mbus_afl_fragment_too_long_fragment;
static int hf_mbus_afl_fragment_error;
static int hf_mbus_afl_fragment_count;
static int hf_mbus_afl_reassembled_in;
static int hf_mbus_afl_reassembled_length;
static int ett_mbus_afl_fragment;
static int ett_mbus_afl_fragments;

/* Dissector Handles. */
static dissector_handle_t mbus_afl_handle;
static dissector_handle_t mbus_tpl_handle;

/* Reassembly table. */
static reassembly_table mbus_reassembly_table;

static const fragment_items mbus_afl_frag_items = {
    /* Fragment subtrees */
    &ett_mbus_afl_fragment,
    &ett_mbus_afl_fragments,
    /* Fragment fields */
    &hf_mbus_afl_fragments,
    &hf_mbus_afl_fragment,
    &hf_mbus_afl_fragment_overlap,
    &hf_mbus_afl_fragment_overlap_conflicts,
    &hf_mbus_afl_fragment_multiple_tails,
    &hf_mbus_afl_fragment_too_long_fragment,
    &hf_mbus_afl_fragment_error,
    &hf_mbus_afl_fragment_count,
    /* Reassembled in field */
    &hf_mbus_afl_reassembled_in,
    /* Reassembled length field */
    &hf_mbus_afl_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "APS Message fragments"
};

#define MBUS_AFL_FCL_FID_MASK        0x00FF
#define MBUS_AFL_FCL_KIP_MASK        0x0200
#define MBUS_AFL_FCL_MACP_MASK       0x0400
#define MBUS_AFL_FCL_MCRP_MASK       0x0800
#define MBUS_AFL_FCL_MLP_MASK        0x1000
#define MBUS_AFL_FCL_MCLP_MASK       0x2000
#define MBUS_AFL_FCL_MF_MASK         0x4000

/* AFL FCL flags */
static int* const afl_fcl_field_flags[] = {
    &hf_mbus_afl_fcl_fid,
    &hf_mbus_afl_fcl_kip,
    &hf_mbus_afl_fcl_macp,
    &hf_mbus_afl_fcl_mcrp,
    &hf_mbus_afl_fcl_mlp,
    &hf_mbus_afl_fcl_mclp,
    &hf_mbus_afl_fcl_mf,
    NULL
};

static uint32_t
generate_mbus_msg_id(const mbus_packet_info_t* mbus_info)
{
    uint32_t msg_id;
    if (mbus_info->wireless) {
        msg_id = mbus_info->security_info.identification_number;
        msg_id ^= mbus_info->security_info.manufacturer;
        msg_id ^= ((uint32_t)mbus_info->security_info.version << 16);
        msg_id ^= ((uint32_t)mbus_info->security_info.device << 24);
    }
    else {
        msg_id = mbus_info->wired_info.address;
    }
    msg_id &= 0x7FFFFFFF;
    msg_id |= (mbus_info->cfield & MBUS_C_FIELD_DIR_MASK) << 31;
    return msg_id;
}

static int
dissect_mbus_afl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    mbus_packet_info_t* mbus_info = (mbus_packet_info_t*)data;

    /* Create the protocol tree */
    proto_item* proto_root = proto_tree_add_protocol_format(tree, proto_mbus_afl, tvb, 0, tvb_captured_length(tvb), "MBus Authentication Fragmentation Layer");
    proto_tree* afl_tree = proto_item_add_subtree(proto_root, ett_mbus_afl);

    proto_tree_add_item(afl_tree, hf_mbus_afl_cifield, tvb, offset, 1, ENC_NA);
    offset += 1;

    uint8_t afl_length = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(afl_tree, hf_mbus_afl_afll, tvb, offset, 1, ENC_NA);
    offset += 1;

    uint16_t afl_fcl = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(afl_tree, tvb, offset, hf_mbus_afl_fcl, ett_mbus_afl_fcl, afl_fcl_field_flags, ENC_LITTLE_ENDIAN);
    offset += 2;
    afl_length -= 2;

    // TODO Dissect fields according to flags in FCL. For now just skip the fields and dissect the payload.
    offset += afl_length;

    tvbuff_t* payload_tvb = tvb_new_subset_remaining(tvb, offset);

    /* Add fragments to reassembler */
    uint32_t block_num = afl_fcl & MBUS_AFL_FCL_FID_MASK;
    if (block_num == 0) {
        /* Not a fragmented message. Call dissector without reassembly */
        call_dissector_with_data(mbus_tpl_handle, payload_tvb, pinfo, proto_tree_get_root(tree), mbus_info);
    }
    else {
        uint32_t msg_id = generate_mbus_msg_id(mbus_info);

        /* Block numbers are counting from 0 in fragment_add_seq_check */
        block_num--;

        bool more_fragment = (afl_fcl & MBUS_AFL_FCL_MF_MASK) != 0;
        fragment_head *frag_msg = fragment_add_seq_check(&mbus_reassembly_table,
                                                         payload_tvb, 0, pinfo, msg_id, NULL,
                                                         block_num, tvb_captured_length(payload_tvb), more_fragment);

        if (more_fragment == false) {
            fragment_set_tot_len(&mbus_reassembly_table, pinfo, msg_id, NULL, block_num + 1);
        }

        tvbuff_t *new_tvb = process_reassembled_data(payload_tvb, 0, pinfo, "Reassembled MBus AFL",
                                                     frag_msg, &mbus_afl_frag_items, NULL, afl_tree);

        if (new_tvb != NULL) {
            /* The reassembly handler defragmented the message */
            call_dissector_with_data(mbus_tpl_handle, new_tvb, pinfo, proto_tree_get_root(tree), mbus_info);
        }
        else {
            /* The reassembly handler could not defragment the message. */
            call_data_dissector(payload_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_mbus_afl(void)
{
    static hf_register_info hf[] = {
        { &hf_mbus_afl_cifield,
            { "CIField", "mbus.afl.cifield", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mbus_ci_field_names_ext,
              0x00, NULL, HFILL } },
        { &hf_mbus_afl_afll,
            { "Length", "mbus.afl.afll", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_afl_fcl,
            { "Control Field", "mbus.afl.fcl", FT_UINT16, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_afl_fcl_fid,
            { "Fragment ID", "mbus.afl.fcl.fid", FT_UINT16, BASE_DEC, NULL,
              0x00FF, NULL, HFILL } },
        { &hf_mbus_afl_fcl_kip,
            { "Key Information Present", "mbus.afl.fcl.kip", FT_BOOLEAN, 16, NULL,
              0x0200, NULL, HFILL } },
        { &hf_mbus_afl_fcl_macp,
            { "MAC Present", "mbus.afl.fcl.macp", FT_BOOLEAN, 16, NULL,
              0x0400, NULL, HFILL } },
        { &hf_mbus_afl_fcl_mcrp,
            { "Message Counter Present", "mbus.afl.fcl.mcrp", FT_BOOLEAN, 16, NULL,
              0x0800, NULL, HFILL } },
        { &hf_mbus_afl_fcl_mlp,
            { "Message Length Present", "mbus.afl.fcl.mlp", FT_BOOLEAN, 16, NULL,
              0x1000, NULL, HFILL } },
        { &hf_mbus_afl_fcl_mclp,
            { "Message Control Present", "mbus.afl.fcl.mclp", FT_BOOLEAN, 16, NULL,
              0x2000, NULL, HFILL } },
        { &hf_mbus_afl_fcl_mf,
            { "More Fragments", "mbus.afl.fcl.mf", FT_BOOLEAN, 16, NULL,
              0x4000, NULL, HFILL } },

        { &hf_mbus_afl_fragments,
            { "Message fragments", "mbus.afl.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
        { &hf_mbus_afl_fragment,
            { "Message fragment", "mbus.afl.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
        { &hf_mbus_afl_fragment_overlap,
            { "Message fragment overlap", "mbus.afl.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
        { &hf_mbus_afl_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "mbus.afl.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
        { &hf_mbus_afl_fragment_multiple_tails,
            { "Message has multiple tail fragments", "mbus.afl.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
        { &hf_mbus_afl_fragment_too_long_fragment,
            { "Message fragment too long", "mbus.afl.fragment.too_long_fragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
        { &hf_mbus_afl_fragment_error,
            { "Message defragmentation error", "mbus.afl.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
        { &hf_mbus_afl_fragment_count,
            { "Message fragment count", "mbus.afl.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }},
        { &hf_mbus_afl_reassembled_in,
            { "Reassembled in", "mbus.afl.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
              NULL, HFILL }},
        { &hf_mbus_afl_reassembled_length,
            { "Reassembled MBus length", "mbus.afl.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
              NULL, HFILL }}
    };

    /* MBus subtrees */
    static int *ett[] = {
        &ett_mbus_afl,
        &ett_mbus_afl_fcl,
        &ett_mbus_afl_fragment,
        &ett_mbus_afl_fragments
    };

    /* Register reassembly table */
    reassembly_table_register(&mbus_reassembly_table, &addresses_reassembly_table_functions);

    proto_mbus_afl = proto_register_protocol("MBus AFL", "MBus AFL", MBUS_PROTOABBREV_AFL);
    proto_register_field_array(proto_mbus_afl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    mbus_afl_handle = register_dissector(MBUS_PROTOABBREV_AFL, dissect_mbus_afl, proto_mbus_afl);
}

void
proto_reg_handoff_mbus_afl(void)
{
    mbus_tpl_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_TPL, proto_mbus_afl);
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
