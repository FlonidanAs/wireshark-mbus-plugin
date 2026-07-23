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
#include <epan/proto_data.h>
#include "packet-wmbus.h"
#include "packet-wmbus-module.h"
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
static int hf_wmbus_response_time;
static int hf_wmbus_response_to_frame;

/* Initialize the subtree pointers */
#define WMBUS_NUM_INDIVIDUAL_ETT        2
#define WMBUS_NUM_DATA_BLOCKS_ETT       20
#define WMBUS_NUM_TOTAL_ETT             (WMBUS_NUM_INDIVIDUAL_ETT + WMBUS_NUM_DATA_BLOCKS_ETT)

static int ett_wmbus;
static int ett_wmbus_dll;
static int ett_wmbus_data_blocks[WMBUS_NUM_DATA_BLOCKS_ETT];

static wmem_tree_t* transaction_unmatched_mbus = NULL;
static wmem_tree_t* transaction_matched_mbus = NULL;

typedef struct {
    uint32_t m2o_frame;
    uint64_t m2o_end_time;
    uint32_t o2m_frame;
} wmbus_transaction_t;

static void create_address_key(char address_key[32], const char* address, uint32_t frame)
{
    snprintf(address_key, 32, "%s_%u", address, frame);
}

static wmbus_transaction_t* try_find_transaction(packet_info *pinfo, const mbus_packet_info_t* mbus_info, const char* frame_key)
{
    // Have we already matched it and moved it to the matched list? If so, return it.
    wmbus_transaction_t* transaction = (wmbus_transaction_t*)wmem_tree_lookup_string(transaction_matched_mbus, frame_key, 0);
    if (transaction != NULL) {
        return transaction;
    }

    char dst_address[32];
    mbus_get_dst_address_from_info(mbus_info, dst_address, sizeof(dst_address));

    // If not, try to find it in the unmatched list.
    // Cap the search to 100 frames back to avoid searching too far back in time.
    for (uint32_t i = 1; i < 100; i++) {
        if (pinfo->num < i) {
            // Avoid underflow
            break;
        }

        char address_key[32];
        create_address_key(address_key, dst_address, pinfo->num - i);
        wmbus_transaction_t* transaction = (wmbus_transaction_t*)wmem_tree_lookup_string(transaction_unmatched_mbus, address_key, 0);
        if (transaction != NULL) {
            // Remove the transaction from the unmatched list and add it to the matched list to avoid matching it again in the future.
            transaction->o2m_frame = pinfo->num;
            wmem_tree_remove_string(transaction_unmatched_mbus, address_key, 0);
            wmem_tree_insert_string(transaction_matched_mbus, frame_key, transaction, 0);
            return transaction;
        }
    }

    // If we didn't find it in either list, return NULL.
    return NULL;
}

static void wmbus_add_check_response_time(packet_info *pinfo, proto_tree *tree, const mbus_packet_info_t* mbus_info, const wmbus_module_packet_t* packet)
{
    char address_str[32];
    mbus_get_src_address_from_info(mbus_info, address_str, sizeof(address_str));

    char frame_key[32];
    create_address_key(frame_key, address_str, pinfo->num);

    if (mbus_is_msg_from_meter(mbus_info->cfield)) {
        if (!PINFO_FD_VISITED(pinfo)) {
            // Insert a new transaction into the unmatched list as a unique entry by using the address + frame number as the key.
            // If we only used the address it would require that the messages was always visited in order, which is not guaranteed.
            wmbus_transaction_t* transaction = wmem_new0(wmem_file_scope(), wmbus_transaction_t);
            transaction->m2o_frame = pinfo->num;
            transaction->m2o_end_time = packet->synctime + packet->airtime;
            wmem_tree_insert_string(transaction_unmatched_mbus, frame_key, transaction, 0);
        }
    }
    else {
        wmbus_transaction_t* transaction = try_find_transaction(pinfo, mbus_info, frame_key);
        if (transaction != NULL) {
            // Calculate response time
            uint64_t response_time_us = packet->synctime - transaction->m2o_end_time;

            // Response must be less than 2 seconds, otherwise we consider it a timeout (not a match).
            const uint64_t mbus_transaction_timeout_us = 2 * 1000000;
            if (response_time_us > mbus_transaction_timeout_us) {
                return;
            }

            nstime_t response_time;
            response_time.secs = response_time_us / 1000000;
            response_time.nsecs = (response_time_us % 1000000) * 1000;

            proto_item* response_time_item = proto_tree_add_time(tree, hf_wmbus_response_time, NULL, 0, 0, &response_time);
            proto_item_set_generated(response_time_item);

            proto_item* response_to_frame_item = proto_tree_add_uint(tree, hf_wmbus_response_to_frame, NULL, 0, 0, transaction->m2o_frame);
            proto_item_set_generated(response_to_frame_item);
        }
    }
}

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

static void
dissect_wmbus_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const wmbus_module_packet_t* packet)
{
    mbus_packet_info_t* mbus_info = p_get_proto_data(wmem_file_scope(), pinfo, proto_wmbus, 0);
    if (!PINFO_FD_VISITED(pinfo) || (mbus_info == NULL)) {
        mbus_info = wmem_new0(wmem_file_scope(), mbus_packet_info_t);
        p_set_proto_data(wmem_file_scope(), pinfo, proto_wmbus, 0, mbus_info);
    }
    mbus_info->wireless = true;

    int offset = 0;

    /* Add Link Layer subtree */
    proto_tree* link_layer_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_wmbus_dll, NULL, "WMBus Data Link Layer");

    /* LField */
    proto_tree_add_item(link_layer_tree, hf_wmbus_len, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* CField */
    uint8_t cfield = mbus_dissect_cfield(tvb, pinfo, link_layer_tree, &offset);

    /* Manufacturer */
    uint16_t manufacturer = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(link_layer_tree, hf_wmbus_manufacturer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Device Id (same as Identification Number) */
    uint32_t device_id = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(link_layer_tree, hf_wmbus_id_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    /* Version */
    uint8_t version = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(link_layer_tree, hf_wmbus_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Device type */
    uint8_t device_type = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(link_layer_tree, hf_wmbus_device_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* Only set below values on first visit. They might have been updated in previous dissections */
    if (!PINFO_FD_VISITED(pinfo)) {
        mbus_info->cfield = cfield;
        mbus_info->wireless_info.link_layer_address.identification_number = device_id;
        mbus_info->wireless_info.link_layer_address.manufacturer = manufacturer;
        mbus_info->wireless_info.link_layer_address.version = version;
        mbus_info->wireless_info.link_layer_address.device_type = device_type;

        // Keep this to avoid breaking the existing code
        mbus_info->security_info.manufacturer = manufacturer;
        mbus_info->security_info.identification_number = device_id;
        mbus_info->security_info.version = version;
        mbus_info->security_info.device = device_type;
        mbus_info->security_info.fields_present = true;
    }

    /* Set end of link layer tree */
    proto_item_set_end(proto_tree_get_parent(link_layer_tree), tvb, offset);

    /* Set address information */
    mbus_set_address_from_info(pinfo, mbus_info);

    /* Check response time */
    wmbus_add_check_response_time(pinfo, link_layer_tree, mbus_info, packet);

    /* Call ELL, AFL or TPL dissector. Depends on the CI Field */
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        uint8_t cifield = tvb_get_uint8(tvb, offset);

        tvbuff_t* new_tvb = tvb_new_subset_length(tvb, offset, tvb_reported_length_remaining(tvb, offset));
        if (mbus_is_ell_ci_field(cifield)) {
            call_dissector_with_data(mbus_ell_handle, new_tvb, pinfo, proto_tree_get_root(tree), mbus_info);
        }
        else if (mbus_is_afl_ci_field(cifield)) {
            call_dissector_with_data(mbus_afl_handle, new_tvb, pinfo, proto_tree_get_root(tree), mbus_info);
        }
        else {
            call_dissector_with_data(mbus_tpl_handle, new_tvb, pinfo, proto_tree_get_root(tree), mbus_info);
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
    wmbus_module_packet_t* packet = (wmbus_module_packet_t*)data;

    /* Create the protocol tree */
    proto_item* proto_root = proto_tree_add_protocol_format(tree, proto_wmbus, tvb, 0, tvb_captured_length(tvb), "WMBus");
    proto_tree* wmbus_tree = proto_item_add_subtree(proto_root, ett_wmbus);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WMBus");
    col_set_str(pinfo->cinfo, COL_INFO, "WMBus");

    tvbuff_t* payload_tvb;

    switch (packet->format) {
        case WMBUS_MODULE_MESSAGE_FORMAT_A:
            payload_tvb = dissect_wmbus_message_format_a(tvb, pinfo, wmbus_tree);
            break;
        case WMBUS_MODULE_MESSAGE_FORMAT_B:
            payload_tvb = dissect_wmbus_message_format_b(tvb, pinfo, wmbus_tree);
            break;
        case WMBUS_MODULE_MESSAGE_FORMAT_NOFRAME:
            payload_tvb = tvb;
            break;
        default:
            // Unknown format
            payload_tvb = NULL;
            break;
    }

    if (payload_tvb != NULL) {
        dissect_wmbus_frame(payload_tvb, pinfo, tree, packet);
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
        { &hf_wmbus_response_time,
            { "Response Time", "wmbus.response_time", FT_RELATIVE_TIME, BASE_NONE, NULL,
              0x00, NULL, HFILL } },
        { &hf_wmbus_response_to_frame,
            { "Response To Frame", "wmbus.response_to_frame", FT_FRAMENUM, BASE_NONE, NULL,
               0x00, NULL, HFILL } },
    };

    /* WMBus subtrees */
    int *ett[WMBUS_NUM_TOTAL_ETT];

    ett[0] = &ett_wmbus;
    ett[1] = &ett_wmbus_dll;

    size_t j = WMBUS_NUM_INDIVIDUAL_ETT;

    /* Initialize wmbus block subtrees */
    for (size_t i = 0; i < WMBUS_NUM_DATA_BLOCKS_ETT; i++, j++) {
        ett[j] = &ett_wmbus_data_blocks[i];
    }

    proto_wmbus = proto_register_protocol("WMBus Protocol", "WMBus", WMBUS_PROTOABBREV);
    proto_register_field_array(proto_wmbus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    transaction_unmatched_mbus = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    transaction_matched_mbus = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

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
