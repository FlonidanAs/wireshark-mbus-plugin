/* packet-wmbus.c
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
#include "packet-wmbus.h"
#include "packet-mbus.h"
#include "packet-mbus-common.h"

/*************************/
/* Function Declarations */
/*************************/
void proto_register_wmbus(void);
void proto_reg_handoff_wmbus(void);

/*************************/
/** Global Variables    **/
/*************************/
/* Dissector Handles. */
static dissector_handle_t wmbus_handle;
static dissector_handle_t mbus_ell_handle;
static dissector_handle_t mbus_afl_handle;
static dissector_handle_t mbus_tpl_handle;

/* Initialize the protocol and registered fields */
static int proto_wmbus;

static int hf_wmbus_data_block_data;
static int hf_wmbus_data_block_crc;
static int hf_wmbus_len;
static int hf_wmbus_manufacturer;
static int hf_wmbus_id_number;
static int hf_wmbus_version;
static int hf_wmbus_device_type;

/* Initialize the subtree pointers */
#define WMBUS_NUM_INDIVIDUAL_ETT        2
#define WMBUS_NUM_DATA_BLOCKS_ETT       20
#define WMBUS_NUM_TOTAL_ETT             (WMBUS_NUM_INDIVIDUAL_ETT + WMBUS_NUM_DATA_BLOCKS_ETT)

static int ett_wmbus;
static int ett_wmbus_dll;
static int ett_wmbus_data_blocks[WMBUS_NUM_DATA_BLOCKS_ETT];

static tvbuff_t*
dissect_wmbus_message_format_b(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    int block_tree_index = 0;
    proto_tree* block_tree;
    int block_len;
    int rem_len = tvb_reported_length_remaining(tvb, offset);
    int buffer_index = 0;
    uint8_t* buffer = (uint8_t *)wmem_alloc(pinfo->pool, rem_len);

    /* Dissect first block - max 128 bytes */
    block_len = rem_len > 128 ? 128 : rem_len;
    rem_len -= block_len;

    block_tree = proto_tree_add_subtree_format(tree, tvb, offset, block_len, ett_wmbus_data_blocks[block_tree_index],
                                               NULL, "Data Block [%d]", block_tree_index);
    block_tree_index++;

    if (block_len < 2) {
        return NULL;
    }

    memcpy(&buffer[buffer_index], (const void*)tvb_memdup(pinfo->pool, tvb, offset, block_len - 2), block_len - 2);
    buffer_index += block_len - 2;

    proto_tree_add_item(block_tree, hf_wmbus_data_block_data, tvb, offset, block_len - 2, ENC_NA);
    offset += block_len - 2;

    proto_tree_add_item(block_tree, hf_wmbus_data_block_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Dissect second block (if more data) */
    if (rem_len >= 2) {
        block_len = rem_len > 128 ? 128 : rem_len;
        rem_len -= block_len;

        block_tree = proto_tree_add_subtree_format(tree, tvb, offset, block_len, ett_wmbus_data_blocks[block_tree_index],
                                                   NULL, "Data Block [%d]", block_tree_index);
        block_tree_index++;

        memcpy(&buffer[buffer_index], (const void*)tvb_memdup(pinfo->pool, tvb, offset, block_len - 2), block_len - 2);
        buffer_index += block_len - 2;

        proto_tree_add_item(block_tree, hf_wmbus_data_block_data, tvb, offset, block_len - 2, ENC_NA);
        offset += block_len - 2;

        proto_tree_add_item(block_tree, hf_wmbus_data_block_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    tvbuff_t* payload_tvb = tvb_new_child_real_data(tvb, buffer, buffer_index, buffer_index);
    add_new_data_source(pinfo, payload_tvb, "WMBus Message");
    return payload_tvb;
}

static tvbuff_t*
dissect_wmbus_message_format_a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    int block_tree_index = 0;
    proto_tree* block_tree;
    int buffer_index = 0;
    uint8_t* buffer = (uint8_t *)wmem_alloc(pinfo->pool, tvb_reported_length_remaining(tvb, offset));

    /* Dissect first block */
    if (tvb_reported_length_remaining(tvb, offset) > 12) {
        block_tree = proto_tree_add_subtree(tree, tvb, offset, 12, ett_wmbus_data_blocks[block_tree_index],
                                            NULL, "Header Block");
        block_tree_index++;

        memcpy(&buffer[buffer_index], (const void*)tvb_memdup(pinfo->pool, tvb, offset, 10), 10);
        buffer_index += 10;

        proto_tree_add_item(block_tree, hf_wmbus_data_block_data, tvb, offset, 10, ENC_NA);
        offset += 10;

        proto_tree_add_item(block_tree, hf_wmbus_data_block_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    /* Dissect "middle" blocks */
    while (tvb_reported_length_remaining(tvb, offset) > 18) {
        block_tree = proto_tree_add_subtree_format(tree, tvb, offset, 18, ett_wmbus_data_blocks[block_tree_index],
                                                   NULL, "Data Block [%d]", block_tree_index - 1);
        block_tree_index++;

        memcpy(&buffer[buffer_index], (const void*)tvb_memdup(pinfo->pool, tvb, offset, 16), 16);
        buffer_index += 16;

        proto_tree_add_item(block_tree, hf_wmbus_data_block_data, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item(block_tree, hf_wmbus_data_block_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    /* Dissect last block */
    int last_size = tvb_reported_length_remaining(tvb, offset);
    if (last_size > 2) {
        block_tree = proto_tree_add_subtree_format(tree, tvb, offset, last_size, ett_wmbus_data_blocks[block_tree_index],
                                                   NULL, "Data Block [%d]", block_tree_index == 0 ? 0 : block_tree_index - 1);

        memcpy(&buffer[buffer_index], (const void*)tvb_memdup(pinfo->pool, tvb, offset, last_size - 2), last_size - 2);
        buffer_index += last_size - 2;

        proto_tree_add_item(block_tree, hf_wmbus_data_block_data, tvb, offset, last_size - 2, ENC_NA);
        offset += last_size - 2;

        proto_tree_add_item(block_tree, hf_wmbus_data_block_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    tvbuff_t* payload_tvb = tvb_new_child_real_data(tvb, buffer, buffer_index, buffer_index);
    add_new_data_source(pinfo, payload_tvb, "WMBus Message");
    return payload_tvb;
}

static void create_address_string(uint16_t manufacturer, uint32_t id, uint8_t version, uint8_t device, char* buffer, size_t buffer_size)
{
    char manufacturer_str[4];
    mbus_manufacturer_id_to_string(manufacturer_str, sizeof(manufacturer_str), manufacturer);
    snprintf(buffer, buffer_size, "%s-%08x-%02x-%02x", manufacturer_str, id, version, device);
}

static void
dissect_wmbus_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const wmbus_message_info_t* wmbus_message_info)
{
    mbus_packet_info_t mbus_info;
    memset(&mbus_info, 0, sizeof(mbus_info));
    mbus_info.wireless = true;

    int offset = 0;

    switch (wmbus_message_info->mode) {
        case PACKET_WMBUS_MESSAGE_M2O_MODE_C:
            col_set_str(pinfo->cinfo, COL_INFO, "M2O Mode C");
            break;
        case PACKET_WMBUS_MESSAGE_M2O_MODE_T:
            col_set_str(pinfo->cinfo, COL_INFO, "M2O Mode T");
            break;
        case PACKET_WMBUS_MESSAGE_O2M_MODE_C:
            col_set_str(pinfo->cinfo, COL_INFO, "O2M Mode C");
            break;
        case PACKET_WMBUS_MESSAGE_O2M_MODE_T:
            col_set_str(pinfo->cinfo, COL_INFO, "O2M Mode T");
            break;
        default:
            break;
    }

    /* Add Link Layer subtree */
    proto_tree* link_layer_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_wmbus_dll, NULL, "WMBus Data Link Layer");

    /* LField */
    proto_tree_add_item(link_layer_tree, hf_wmbus_len, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* CField */
    mbus_info.cfield = mbus_dissect_cfield(tvb, pinfo, link_layer_tree, &offset);

    /* Manufacturer */
    mbus_info.security_info.manufacturer = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(link_layer_tree, hf_wmbus_manufacturer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Device Id (same as Identification Number) */
    mbus_info.security_info.identification_number = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(link_layer_tree, hf_wmbus_id_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Version */
    mbus_info.security_info.version = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(link_layer_tree, hf_wmbus_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Device type */
    mbus_info.security_info.device = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(link_layer_tree, hf_wmbus_device_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    mbus_info.security_info.fields_present = true;

    /* Set end of link layer tree */
    proto_item_set_end(proto_tree_get_parent(link_layer_tree), tvb, offset);

    /* Set address information */
    char address_str[ITEM_LABEL_LENGTH];
    create_address_string(mbus_info.security_info.manufacturer, mbus_info.security_info.identification_number,
                          mbus_info.security_info.version, mbus_info.security_info.device,
                          address_str, sizeof(address_str));
    mbus_set_address_and_port_info(pinfo, mbus_info.cfield, address_str);

    /* Call ELL, AFL or TPL dissector. Depends on the CI Field */
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        uint8_t cifield = tvb_get_uint8(tvb, offset);

        tvbuff_t* new_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset));
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
} /*dissect_wmbus_frame*/

static int
dissect_wmbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Reject the packet if data is NULL */
    if (data == NULL) {
        return 0;
    }
    wmbus_message_info_t* wmbus_message_info = (wmbus_message_info_t*)data;

    /* Create the protocol tree */
    proto_item* proto_root = proto_tree_add_protocol_format(tree, proto_wmbus, tvb, 0, tvb_captured_length(tvb), "WMBus");
    proto_tree* wmbus_tree = proto_item_add_subtree(proto_root, ett_wmbus);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WMBus");
    col_set_str(pinfo->cinfo, COL_INFO, "WMBus");

    tvbuff_t* payload_tvb;

    switch (wmbus_message_info->format) {
        case PACKET_WMBUS_MESSAGE_FORMAT_A:
            payload_tvb = dissect_wmbus_message_format_a(tvb, pinfo, wmbus_tree);
            break;
        case PACKET_WMBUS_MESSAGE_FORMAT_B:
            payload_tvb = dissect_wmbus_message_format_b(tvb, pinfo, wmbus_tree);
            break;
        default:
            // Unknown format
            payload_tvb = NULL;
            break;
    }

    if (payload_tvb != NULL) {
        dissect_wmbus_frame(payload_tvb, pinfo, tree, wmbus_message_info);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_wmbus(void)
{
    static hf_register_info hf[] = {
        { &hf_wmbus_data_block_data,
            { "Data", "wmbus.dll.block.data", FT_BYTES, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_wmbus_data_block_crc,
            { "CRC", "wmbus.dll.block.crc", FT_UINT16, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_wmbus_len,
            { "Length", "wmbus.dll.len", FT_UINT8, BASE_DEC, NULL,
              0x00, NULL, HFILL } },
        { &hf_wmbus_manufacturer,
            { "Manufacturer", "wmbus.dll.manufacturer", FT_UINT16, BASE_CUSTOM, CF_FUNC(mbus_decode_manufacturer_id),
              0x00, NULL, HFILL } },
        { &hf_wmbus_id_number,
            { "Identification Number", "wmbus.dll.id_number", FT_UINT32, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_wmbus_version,
            { "Version", "wmbus.dll.version", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_wmbus_device_type,
            { "Device Type", "wmbus.dll.device_type", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
    };

    /* MBus subtrees */
    int *ett[WMBUS_NUM_TOTAL_ETT];

    ett[0] = &ett_wmbus;
    ett[1] = &ett_wmbus_dll;

    size_t j = WMBUS_NUM_INDIVIDUAL_ETT;

    /* Initialize mbus application block subtrees */
    for (size_t i = 0; i < WMBUS_NUM_DATA_BLOCKS_ETT; i++, j++) {
        ett[j] = &ett_wmbus_data_blocks[i];
    }

    proto_wmbus = proto_register_protocol("WMBus Protocol", "WMBus", WMBUS_PROTOABBREV);
    proto_register_field_array(proto_wmbus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    wmbus_handle = register_dissector(WMBUS_PROTOABBREV, dissect_wmbus, proto_wmbus);
}

void
proto_reg_handoff_wmbus(void)
{
    mbus_ell_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_ELL, proto_wmbus);
    mbus_afl_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_AFL, proto_wmbus);
    mbus_tpl_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_TPL, proto_wmbus);
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
