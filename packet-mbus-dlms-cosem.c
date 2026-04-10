/* packet-mbus-dlms-cosem.c
 * Routines for MBus COSEM Application Layer dissection.
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
#include <epan/proto_data.h>
#include "packet-mbus-common.h"

/*************************/
/* Function Declarations */
/*************************/
void proto_register_mbus_dlms(void);
void proto_reg_handoff_mbus_dlms(void);

/*************************/
/** Global Variables    **/
/*************************/
/* Dissector Handles. */
static dissector_handle_t mbus_dlms_cosem_handle;

/* Initialize the protocol and registered fields */
static int proto_mbus_dlms;

/* Initialize the subtree pointers */
static int ett_mbus_dlms;

static int dissect_mbus_dlms_cosem(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Create the protocol tree */
    proto_item* proto_root = proto_tree_add_protocol_format(tree, proto_mbus_dlms, tvb, 0, -1, "MBus DLMS");
    proto_tree* dlms_tree = proto_item_add_subtree(proto_root, ett_mbus_dlms);

    call_data_dissector(tvb, pinfo, dlms_tree);
    return tvb_captured_length(tvb);
}

void proto_register_mbus_dlms(void)
{
    /* MBus subtrees */
    int *ett[] = {
        &ett_mbus_dlms
    };

    proto_mbus_dlms = proto_register_protocol("MBus DLMS", "MBus DLMS", MBUS_PROTOABBREV_DLMS);
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    mbus_dlms_cosem_handle = register_dissector(MBUS_PROTOABBREV_DLMS, dissect_mbus_dlms_cosem, proto_mbus_dlms);
}

void
proto_reg_handoff_mbus_dlms(void)
{
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
