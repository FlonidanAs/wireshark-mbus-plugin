/* packet-mbus-ell.c
 * Routines for MBus Extended Link Layer (ELL) dissection.
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
#include "packet-mbus-common.h"

/*************************/
/* Function Declarations */
/*************************/
void proto_register_mbus_ell(void);
void proto_reg_handoff_mbus_ell(void);

/*************************/
/** Global Variables    **/
/*************************/
/* Initialize the protocol and registered fields */
static int proto_mbus_ell;

static int hf_mbus_ell_cifield;
static int hf_mbus_ell_cc;
static int hf_mbus_ell_cc_extended_delay;
static int hf_mbus_ell_cc_repeated_access;
static int hf_mbus_ell_cc_accessibility;
static int hf_mbus_ell_cc_priority;
static int hf_mbus_ell_cc_hop_count;
static int hf_mbus_ell_cc_synchronized;
static int hf_mbus_ell_cc_response_delay;
static int hf_mbus_ell_cc_bi_directional;
static int hf_mbus_ell_acc;

static int ett_mbus_ell;
static int ett_mbus_ell_cc;

/* Dissector Handles. */
static dissector_handle_t mbus_ell_handle;
static dissector_handle_t mbus_afl_handle;
static dissector_handle_t mbus_tpl_handle;

/* ELL Communication Control flags */
static int* const ell_cc_field_flags[] = {
    &hf_mbus_ell_cc_extended_delay,
    &hf_mbus_ell_cc_repeated_access,
    &hf_mbus_ell_cc_accessibility,
    &hf_mbus_ell_cc_priority,
    &hf_mbus_ell_cc_hop_count,
    &hf_mbus_ell_cc_synchronized,
    &hf_mbus_ell_cc_response_delay,
    &hf_mbus_ell_cc_bi_directional,
    NULL
};

static void dissect_extended_link_layer_1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int* offset)
{
    proto_tree_add_item(tree, hf_mbus_ell_cifield, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    proto_tree_add_bitmask(tree, tvb, *offset, hf_mbus_ell_cc, ett_mbus_ell_cc, ell_cc_field_flags, ENC_NA);
    *offset += 1;

    proto_tree_add_item(tree, hf_mbus_ell_acc, tvb, *offset, 1, ENC_NA);
    *offset += 1;
}

static int
dissect_mbus_ell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    /* Create the protocol tree */
    proto_item* proto_root = proto_tree_add_protocol_format(tree, proto_mbus_ell, tvb, 0, -1, "MBus Extended Link Layer");
    proto_tree* mbus_ell_tree = proto_item_add_subtree(proto_root, ett_mbus_ell);

    /* Check for ELL (Extended Link Layer) */
    uint8_t cifield = tvb_get_uint8(tvb, offset);
    switch (cifield) {
        case ExtendedLinkLayer1:
            dissect_extended_link_layer_1(tvb, pinfo, mbus_ell_tree, &offset);
            break;
        case ExtendedLinkLayer2:
            offset += 1 + 8;
            break;
        case ExtendedLinkLayer3:
            offset += 1 + 10;
            break;
        case ExtendedLinkLayer4:
            offset += 1 + 16;
            break;
    }

    /* Set end of protocol tree */
    proto_item_set_end(proto_root, tvb, offset);

    /* Call mbus AFL or TPL dissector. Depends on the CI Field */
    cifield = tvb_get_uint8(tvb, offset);
    tvbuff_t* new_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset));
    if (cifield == AuthenticationFragmentationLayer) {
        call_dissector_with_data(mbus_afl_handle, new_tvb, pinfo, proto_tree_get_root(tree), data);
    }
    else {
        call_dissector_with_data(mbus_tpl_handle, new_tvb, pinfo, proto_tree_get_root(tree), data);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_mbus_ell(void)
{
    static hf_register_info hf[] = {
        { &hf_mbus_ell_cifield,
            { "CIField", "mbus.ell.cifield", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mbus_ci_field_names_ext,
              0x00, NULL, HFILL } },
        { &hf_mbus_ell_cc,
            { "Communication Control", "mbus.ell.cc", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_ell_cc_extended_delay,
            { "Extended Delay", "mbus.ell.cc.x", FT_BOOLEAN, 8, NULL,
              0x01, NULL, HFILL } },
        { &hf_mbus_ell_cc_repeated_access,
            { "Repeated Access", "mbus.ell.cc.r", FT_BOOLEAN, 8, NULL,
              0x02, NULL, HFILL } },
        { &hf_mbus_ell_cc_accessibility,
            { "Accessibility", "mbus.ell.cc.a", FT_BOOLEAN, 8, NULL,
              0x04, NULL, HFILL } },
        { &hf_mbus_ell_cc_priority,
            { "Priority", "mbus.ell.cc.p", FT_BOOLEAN, 8, NULL,
              0x08, NULL, HFILL } },
        { &hf_mbus_ell_cc_hop_count,
            { "Hop Count", "mbus.ell.cc.h", FT_BOOLEAN, 8, NULL,
              0x10, NULL, HFILL } },
        { &hf_mbus_ell_cc_synchronized,
            { "Synchronized", "mbus.ell.cc.s", FT_BOOLEAN, 8, NULL,
              0x20, NULL, HFILL } },
        { &hf_mbus_ell_cc_response_delay,
            { "Response delay", "mbus.ell.cc.d", FT_BOOLEAN, 8, NULL,
              0x40, NULL, HFILL } },
        { &hf_mbus_ell_cc_bi_directional,
            { "Bi-directional", "mbus.ell.cc.b", FT_BOOLEAN, 8, NULL,
              0x80, NULL, HFILL } },
        { &hf_mbus_ell_acc,
            { "Access Number", "mbus.ell.acc", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } }
    };

    /* MBus subtrees */
    static int *ett[] = {
        &ett_mbus_ell,
        &ett_mbus_ell_cc
    };

    proto_mbus_ell = proto_register_protocol("MBus ELL", "MBus ELL", MBUS_PROTOABBREV_ELL);
    proto_register_field_array(proto_mbus_ell, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    mbus_ell_handle = register_dissector(MBUS_PROTOABBREV_ELL, dissect_mbus_ell, proto_mbus_ell);
}

void
proto_reg_handoff_mbus_ell(void)
{
    mbus_tpl_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_TPL, proto_mbus_ell);
    mbus_afl_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_AFL, proto_mbus_ell);
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
