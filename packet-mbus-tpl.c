/* packet-mbus-tpl.c
 * Routines for MBus Transport Layer (TPL) dissection.
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
#include "packet-mbus-common.h"
#include "packet-mbus-security.h"

enum {
    TPL_HEADER_BLANK,
    TPL_HEADER_NONE,
    TPL_HEADER_SHORT,
    TPL_HEADER_LONG
};

typedef struct {
    uint8_t cifield;
    uint8_t tpl_header;
} CiFieldTPLHeader_t;

static const CiFieldTPLHeader_t ci_field_tpl_header[] = {
    { ApplicationResetOrSelectToDeviceNoHeader, TPL_HEADER_NONE },
    { DataSend, TPL_HEADER_NONE },
    { SelectionOfDevice, TPL_HEADER_NONE },
    { ApplicationResetOrSelectToDeviceLongHeader, TPL_HEADER_LONG },
    { CommandToDeviceShortHeader, TPL_HEADER_SHORT },
    { CommandToDeviceLongHeader, TPL_HEADER_LONG },
    { SynchroniseAction, TPL_HEADER_BLANK },
    { TlsFromDeviceShortHeader, TPL_HEADER_SHORT },
    { TlsFromDeviceLongHeader, TPL_HEADER_LONG },
    { CommandToDeviceDLMSLongHeader, TPL_HEADER_LONG },
    { CommandToDeviceDLMSShortHeader, TPL_HEADER_SHORT },
    { CommandToDeviceOBISTypeLongHeader, TPL_HEADER_LONG },
    { CommandToDeviceOBISTypeShortHeader, TPL_HEADER_SHORT },
    { ResponseFromDeviceFormatFrameNoHeader, TPL_HEADER_NONE },
    { ResponseFromDeviceFormatFrameShortHeader, TPL_HEADER_SHORT },
    { ResponseFromDeviceFormatFrameLongHeader, TPL_HEADER_LONG },
    { TimeSyncToDeviceLongHeader_1, TPL_HEADER_LONG },
    { TimeSyncToDeviceLongHeader_2, TPL_HEADER_LONG },
    { ApplicationErrorFromDeviceShortHeader, TPL_HEADER_SHORT },
    { ApplicationErrorFromDeviceLongHeader, TPL_HEADER_LONG },
    { ApplicationErrorFromDeviceNoHeader, TPL_HEADER_NONE },
    { AlarmFromDeviceNoHeader, TPL_HEADER_NONE },
    { ResponseFromDeviceLongHeader, TPL_HEADER_LONG },
    { ResponseFromDeviceCompactFrameLongHeader, TPL_HEADER_LONG },
    { AlarmFromDeviceShortHeader, TPL_HEADER_SHORT },
    { AlarmFromDeviceLongHeader, TPL_HEADER_LONG },
    { ResponseFromDeviceNoHeader, TPL_HEADER_NONE },
    { ResponseFromDeviceCompactFrameNoHeader, TPL_HEADER_NONE },
    { ResponseFromDeviceShortHeader, TPL_HEADER_SHORT },
    { ResponseFromDeviceCompactFrameShortHeader, TPL_HEADER_SHORT },
    { ResponseFromDeviceDLMSLongHeader, TPL_HEADER_LONG },
    { ResponseFromDeviceDLMSShortHeader, TPL_HEADER_SHORT },
    { ResponseFromDeviceOBISLongHeader, TPL_HEADER_LONG },
    { ResponseFromDeviceOBISShortHeader, TPL_HEADER_SHORT },
    { TransportLayerToDeviceLongHeader, TPL_HEADER_LONG },
    { NetworkLayerData, TPL_HEADER_BLANK },
    { ReservedForNetworkManagementData, TPL_HEADER_BLANK },
    { NetworkManagementData, TPL_HEADER_BLANK },
    { TransportLayerToDeviceCompactFrameLongHeader, TPL_HEADER_LONG },
    { TransportLayerToDeviceFormatFrameLongHeader, TPL_HEADER_LONG },
    { ReservedForNetworkManagementDataFromDevice, TPL_HEADER_BLANK },
    { TransportLayerFromDeviceShortHeader, TPL_HEADER_SHORT },
    { TransportLayerFromDeviceLongHeader, TPL_HEADER_LONG },
    { AuthenticationFragmentationLayer, TPL_HEADER_BLANK },
    { TlsToDeviceShortHeader, TPL_HEADER_SHORT },
    { TlsToDeviceLongHeader, TPL_HEADER_LONG },
    { SetBaudRateTo8192Baud, TPL_HEADER_BLANK },
    { SetBaudRateTo10922Baud, TPL_HEADER_BLANK },
    { SetBaudRateTo300Baud, TPL_HEADER_BLANK },
    { SetBaudRateTo600Baud, TPL_HEADER_BLANK },
    { SetBaudRateTo1200Baud, TPL_HEADER_BLANK },
    { SetBaudRateTo2400Baud, TPL_HEADER_BLANK },
    { SetBaudRateTo4800Baud, TPL_HEADER_BLANK },
    { SetBaudRateTo9600Baud, TPL_HEADER_BLANK },
    { SetBaudRateTo19200Baud, TPL_HEADER_BLANK },
    { SetBaudRateTo38400Baud, TPL_HEADER_BLANK },
    { ImageTransferCommandLongHeader, TPL_HEADER_LONG },
    { ImageTransferResponseShortHeader, TPL_HEADER_SHORT },
    { ImageTransferResponseLongHeader, TPL_HEADER_LONG }
};

static const value_string mbus_config_ext_mode_13_names[] = {
    { 0x00, "TLSCHAN" },
    { 0x01, "TLSPROT" },
    { 0, NULL }
};

/*************************/
/* Function Declarations */
/*************************/
void proto_register_mbus_tpl(void);
void proto_reg_handoff_mbus_tpl(void);

/*************************/
/** Global Variables    **/
/*************************/
/* Dissector Handles. */
static dissector_handle_t mbus_tpl_handle;
static dissector_handle_t mbus_apl_handle;
static dissector_handle_t mbus_dlms_cosem_handle;

/* Initialize the protocol and registered fields */
static int proto_mbus_tpl;

static int hf_mbus_cifield;
static int hf_mbus_cifield_dlms;
static int hf_mbus_cifield_dlms_fin;
static int hf_mbus_cifield_dlms_frag_count;
static int hf_mbus_access_counter;
static int hf_mbus_status;
static int hf_mbus_config;
static int hf_mbus_config_ext_mode7;
static int hf_mbus_config_ext_mode13;
static int hf_mbus_id_number;
static int hf_mbus_manufacturer;
static int hf_mbus_version;
static int hf_mbus_device_type;

/* Initialize the subtree pointers */
static int ett_mbus_tpl;
static int ett_mbus_cifield_dlms;

/* dlms ci field flags */
static int* const cifield_dlms_flags[] = {
    &hf_mbus_cifield_dlms_fin,
    &hf_mbus_cifield_dlms_frag_count,
    NULL
};

static void dissect_mbus_common_layers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, mbus_packet_info_t* mbus_info)
{
    int offset = 0;
    mbus_packet_info_t mbus_packet_info;
    if (mbus_info != NULL) {
        memcpy(&mbus_packet_info, mbus_info, sizeof(mbus_packet_info_t));
    }
    else {
        memset(&mbus_packet_info, 0, sizeof(mbus_packet_info_t));
    }

    /* Create the protocol tree */
    proto_item* proto_root = proto_tree_add_protocol_format(tree, proto_mbus_tpl, tvb, offset, -1, "MBus Transport Layer");
    proto_tree* transport_layer_tree = proto_item_add_subtree(proto_root, ett_mbus_tpl);

    /* CIField */
    mbus_packet_info.ciField = tvb_get_uint8(tvb, offset);
    if (mbus_is_dlms_ci_field(mbus_packet_info.ciField)) {
        proto_tree_add_bitmask(transport_layer_tree, tvb, offset, hf_mbus_cifield_dlms, ett_mbus_cifield_dlms, cifield_dlms_flags, ENC_LITTLE_ENDIAN);
        offset += 1;
        tvbuff_t* payload_tvb = tvb_new_subset_remaining(tvb, offset);
        if (tvb_reported_length(payload_tvb) > 0) {
            call_dissector(mbus_dlms_cosem_handle, payload_tvb, pinfo, proto_tree_get_root(tree));
        }
        return;
    }
    else {
        proto_tree_add_item(transport_layer_tree, hf_mbus_cifield, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    for (size_t i = 0; i < array_length(ci_field_tpl_header); i++) {
        if (ci_field_tpl_header[i].cifield == mbus_packet_info.ciField) {
            switch (ci_field_tpl_header[i].tpl_header) {
                case TPL_HEADER_BLANK:
                case TPL_HEADER_NONE:
                    mbus_packet_info.security_info.configField = 0;
                    if (mbus_info == NULL) {
                        mbus_packet_info.security_info.fields_present = false;
                    }
                    break;
                case TPL_HEADER_SHORT:
                    proto_tree_add_item(transport_layer_tree, hf_mbus_access_counter, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(transport_layer_tree, hf_mbus_status, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    mbus_packet_info.security_info.configField = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(transport_layer_tree, hf_mbus_config, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    switch ((mbus_packet_info.security_info.configField & MBUS_CONFIG_MODE_MASK) >> MBUS_CONFIG_MODE_SHIFT) {
                        case 7:
                            proto_tree_add_item(transport_layer_tree, hf_mbus_config_ext_mode7, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            break;
                        case 13:
                            mbus_packet_info.security_info.configFieldExtension = tvb_get_uint8(tvb, offset);
                            proto_tree_add_item(transport_layer_tree, hf_mbus_config_ext_mode13, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            break;
                        default:
                            break;
                    }
                    if (mbus_info == NULL) {
                        mbus_packet_info.security_info.fields_present = false;
                    }
                    break;
                case TPL_HEADER_LONG:
                    mbus_packet_info.security_info.identification_number = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(transport_layer_tree, hf_mbus_id_number, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    mbus_packet_info.security_info.manufacturer = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(transport_layer_tree, hf_mbus_manufacturer, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    mbus_packet_info.security_info.version = tvb_get_uint8(tvb, offset);
                    proto_tree_add_item(transport_layer_tree, hf_mbus_version, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    mbus_packet_info.security_info.device = tvb_get_uint8(tvb, offset);
                    proto_tree_add_item(transport_layer_tree, hf_mbus_device_type, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(transport_layer_tree, hf_mbus_access_counter, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    proto_tree_add_item(transport_layer_tree, hf_mbus_status, tvb, offset, 1, ENC_NA);
                    offset += 1;
                    mbus_packet_info.security_info.configField = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
                    proto_tree_add_item(transport_layer_tree, hf_mbus_config, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    switch ((mbus_packet_info.security_info.configField & MBUS_CONFIG_MODE_MASK) >> MBUS_CONFIG_MODE_SHIFT) {
                        case 7:
                            proto_tree_add_item(transport_layer_tree, hf_mbus_config_ext_mode7, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            break;
                        case 13:
                            mbus_packet_info.security_info.configFieldExtension = tvb_get_uint8(tvb, offset);
                            proto_tree_add_item(transport_layer_tree, hf_mbus_config_ext_mode13, tvb, offset, 1, ENC_NA);
                            offset += 1;
                            break;
                        default:
                            break;
                    }
                    mbus_packet_info.security_info.fields_present = true;
                    break;
                default:
                    break;
            }
            break;
        }
    }

    /* Set end of header */
    proto_item_set_end(proto_tree_get_parent(transport_layer_tree), tvb, offset);

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        tvbuff_t* payload_tvb = tvb_new_subset_remaining(tvb, offset);

        if ((mbus_packet_info.security_info.configField & MBUS_CONFIG_MODE_MASK) != 0) {
            uint16_t encryption_mode = (mbus_packet_info.security_info.configField & MBUS_CONFIG_MODE_MASK) >> MBUS_CONFIG_MODE_SHIFT;
            if (encryption_mode == 13) {
                /* Encryption mode 13 indicates (D)TLS on the application layer.
                 * Do not try to decrypt it here, but instead let the application layer handle it */
            }
            else {
                payload_tvb = dissect_mbus_secure(payload_tvb, pinfo, transport_layer_tree, 0, &mbus_packet_info.security_info);
                if (payload_tvb == NULL) {
                    /* If payload_tvb is NULL, then the security decryption failed */
                    return;
                }
            }
        }

        /* Call application layer dissector */
        if (tvb_reported_length(payload_tvb) > 0) {
            call_dissector_with_data(mbus_apl_handle, payload_tvb, pinfo, proto_tree_get_root(tree), &mbus_packet_info);
        }
    }
}

static int dissect_mbus_tpl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    dissect_mbus_common_layers(tvb, pinfo, tree, (mbus_packet_info_t*)data);
    return tvb_captured_length(tvb);
}

void proto_register_mbus_tpl(void)
{
    static hf_register_info hf[] = {
        { &hf_mbus_cifield,
            { "CIField", "mbus.tpl.cifield", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &mbus_ci_field_names_ext,
              0x00, NULL, HFILL } },
        { &hf_mbus_cifield_dlms,
            { "CIField DLMS", "mbus.tpl.cifield_dlms", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },
        { &hf_mbus_cifield_dlms_fin,
            { "Final", "mbus.tpl.cifield_dlms.fin", FT_BOOLEAN, 8, NULL,
              0x10, NULL, HFILL } },
        { &hf_mbus_cifield_dlms_frag_count,
            { "Fragment Count", "mbus.tpl.cifield_dlms.frag_count", FT_UINT8, BASE_DEC, NULL,
              0x0F, NULL, HFILL } },

        { &hf_mbus_access_counter,
            { "Access Counter", "mbus.tpl.access_counter", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_status,
            { "Status", "mbus.tpl.status", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_config,
            { "Config", "mbus.tpl.config", FT_UINT16, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_config_ext_mode7,
            { "Config Ext Mode 7", "mbus.tpl.config_ext_mode7", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_config_ext_mode13,
            { "Config Ext Mode 13", "mbus.tpl.config_ext_mode13", FT_UINT8, BASE_HEX, VALS(mbus_config_ext_mode_13_names),
              0x00, NULL, HFILL } },

        { &hf_mbus_id_number,
            { "Identification Number", "mbus.tpl.id_number", FT_UINT32, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_manufacturer,
            { "Manufacturer", "mbus.tpl.manufacturer", FT_UINT16, BASE_CUSTOM, CF_FUNC(mbus_decode_manufacturer_id),
              0x00, NULL, HFILL } },

        { &hf_mbus_version,
            { "Version", "mbus.tpl.version", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } },

        { &hf_mbus_device_type,
            { "Device Type", "mbus.tpl.device_type", FT_UINT8, BASE_HEX, NULL,
              0x00, NULL, HFILL } }
    };

    /* MBus subtrees */
    int *ett[] = {
        &ett_mbus_tpl,
        &ett_mbus_cifield_dlms
    };

    proto_mbus_tpl = proto_register_protocol("MBus TPL", "MBus TPL", MBUS_PROTOABBREV_TPL);
    proto_register_field_array(proto_mbus_tpl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    mbus_tpl_handle = register_dissector(MBUS_PROTOABBREV_TPL, dissect_mbus_tpl, proto_mbus_tpl);

    /* Register the security dissector */
    mbus_security_register(NULL, proto_mbus_tpl);
}

void
proto_reg_handoff_mbus_tpl(void)
{
    mbus_apl_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_APL, proto_mbus_tpl);
    mbus_dlms_cosem_handle = find_dissector_add_dependency(MBUS_PROTOABBREV_DLMS, proto_mbus_tpl);
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
