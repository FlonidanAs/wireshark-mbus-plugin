/* packet-mbus-common.h
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
#include "packet-mbus-common.h"
#include "epan/conversation.h"

VALUE_STRING_ARRAY(mbus_ci_field_names);
value_string_ext mbus_ci_field_names_ext = VALUE_STRING_EXT_INIT(mbus_ci_field_names);

bool mbus_is_dlms_ci_field(uint8_t ciField)
{
    return (ciField >= DLMSBasedApplicationMinimumAllowed) &&
           (ciField <= DLMSBasedApplicationMaximumAllowed);
}

bool mbus_is_ell_ci_field(uint8_t ciField)
{
    return (ciField == ExtendedLinkLayer1) ||
           (ciField == ExtendedLinkLayer2) ||
           (ciField == ExtendedLinkLayer3) ||
           (ciField == ExtendedLinkLayer4);
}

bool mbus_is_afl_ci_field(uint8_t ciField)
{
    return (ciField == AuthenticationFragmentationLayer);
}

bool mbus_is_compact_frame_ci_field(uint8_t ciField)
{
    return (ciField == ResponseFromDeviceCompactFrameNoHeader) ||
           (ciField == ResponseFromDeviceCompactFrameShortHeader) ||
           (ciField == ResponseFromDeviceCompactFrameLongHeader);
}

bool mbus_is_image_transfer_ci_field(uint8_t ciField)
{
    return (ciField == ImageTransferCommandLongHeader) ||
           (ciField == ImageTransferResponseShortHeader) ||
           (ciField == ImageTransferResponseLongHeader);
}

bool mbus_is_tls_ci_field(uint8_t ciField)
{
    return (ciField == TlsFromDeviceShortHeader) ||
           (ciField == TlsFromDeviceLongHeader) ||
           (ciField == TlsToDeviceShortHeader) ||
           (ciField == TlsToDeviceLongHeader);
}

void mbus_manufacturer_id_to_string(char *s, size_t buffer_size, uint16_t value)
{
    char letters[4];

    uint8_t letter;
    uint16_t remainder = value;

    // 1st letter
    letter = remainder / 32 / 32;
    remainder -= letter * 32 * 32;
    letters[0] = (char)(letter + 64);

    // 2nd letter
    letter = remainder / 32;
    remainder -= letter * 32;
    letters[1] = (char)(letter + 64);

    // 3rd letter
    letter = (uint8_t)remainder;
    letters[2] = (char)(letter + 64);

    letters[3] = '\0';

    snprintf(s, buffer_size, "%s", letters);
}

void mbus_decode_manufacturer_id(char *s, uint16_t value)
{
    char letters[4];
    mbus_manufacturer_id_to_string(letters, sizeof(letters), value);
    snprintf(s, ITEM_LABEL_LENGTH, "0x%4X [%s]", value, letters);
}

bool mbus_is_msg_from_meter(uint8_t cfield)
{
    bool direction_bit_set = (cfield & MBUS_C_FIELD_DIR_MASK) != 0U;
    uint8_t function = cfield & MBUS_C_FIELD_FUNC_MASK;

    bool msg_from_meter;
    switch (function) {
        case 0x00: // SND_NKE or ACK. Check direction bit to determine direction
            msg_from_meter = !direction_bit_set;
            break;
        case 0x03: // SND_UD. This message is always to the meter.
        case 0x0A: // REQ_UD1. This message is always to the meter.
        case 0x0B: // REQ_UD2. This message is always to the meter.
            msg_from_meter = false;
            break;
        case 0x04: // SND_NR. This message is always from the meter.
        case 0x06: // SND_IR. This message is always from the meter.
        case 0x07: // ACC_NR. Assume it's from the meter...
        case 0x08: // ACC_DMD. Assume it's from the meter...
            msg_from_meter = true;
            break;
        default:
            // Assume it's from the meter...
            msg_from_meter = true;
            break;
    }
    return msg_from_meter;
}

static void create_address_string(const mbus_address_t* address, char* buffer, size_t buffer_size)
{
    char manufacturer_str[4];
    mbus_manufacturer_id_to_string(manufacturer_str, sizeof(manufacturer_str), address->manufacturer);
    snprintf(buffer, buffer_size, "%s-%08x-%02x-%02x", manufacturer_str, address->identification_number,
             address->version, address->device_type);
}

static void format_prefixed_address(char prefix, const char* addr,
                                    char* buffer, size_t buffer_size)
{
    if (addr == NULL || addr[0] == '\0') {
        snprintf(buffer, buffer_size, "%c", prefix);
    }
    else {
        snprintf(buffer, buffer_size, "%c:%s", prefix, addr);
    }
}

static char get_src_prefix(uint8_t cfield)
{
    return mbus_is_msg_from_meter(cfield) ? 'M' : 'O';
}

static char get_dst_prefix(uint8_t cfield)
{
    return mbus_is_msg_from_meter(cfield) ? 'O' : 'M';
}

void mbus_set_address(packet_info *pinfo, uint8_t cfield, const char* src_address, const char* dst_address)
{
    char src_addr[ITEM_LABEL_LENGTH];
    char dst_addr[ITEM_LABEL_LENGTH];

    format_prefixed_address(get_src_prefix(cfield), src_address, src_addr, sizeof(src_addr));
    format_prefixed_address(get_dst_prefix(cfield), dst_address, dst_addr, sizeof(dst_addr));

    char* src_addr_wmem = wmem_strdup_printf(pinfo->pool, "%s", src_addr);
    char* dst_addr_wmem = wmem_strdup_printf(pinfo->pool, "%s", dst_addr);

    set_address(&pinfo->dl_dst, AT_STRINGZ, (int)strlen(dst_addr_wmem) + 1, dst_addr_wmem);
    copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);

    set_address(&pinfo->dl_src, AT_STRINGZ, (int)strlen(src_addr_wmem) + 1, src_addr_wmem);
    copy_address_shallow(&pinfo->src, &pinfo->dl_src);

    // Set source and destination port. This is important for conversations when MBus is encapsulated in another protocol (e.g. TCP or UDP)
    // An example of this is MBus captured using udpdump.
    // MBus doesn't have ports, so we just set them to 0.
    pinfo->srcport = 0;
    pinfo->destport = 0;
}

void mbus_set_address_from_info(packet_info *pinfo, const mbus_packet_info_t* packet_info)
{
    char src_address_str[ITEM_LABEL_LENGTH];
    create_address_string(&packet_info->wireless_info.link_layer_address, src_address_str, sizeof(src_address_str));

    char dst_address_str[ITEM_LABEL_LENGTH];
    create_address_string(&packet_info->wireless_info.destination_address, dst_address_str, sizeof(dst_address_str));

    mbus_set_address(pinfo, packet_info->cfield, src_address_str,
        packet_info->wireless_info.destination_present ? dst_address_str : NULL);
}

void mbus_get_src_address_from_info(const mbus_packet_info_t* packet_info, char* buffer, size_t buffer_size)
{
    char addr[ITEM_LABEL_LENGTH];
    create_address_string(&packet_info->wireless_info.link_layer_address, addr, sizeof(addr));
    format_prefixed_address(get_src_prefix(packet_info->cfield), addr, buffer, buffer_size);
}

void mbus_get_dst_address_from_info(const mbus_packet_info_t* packet_info, char* buffer, size_t buffer_size)
{
    char addr[ITEM_LABEL_LENGTH];
    create_address_string(&packet_info->wireless_info.destination_address, addr, sizeof(addr));
    format_prefixed_address(get_dst_prefix(packet_info->cfield), addr, buffer, buffer_size);
}

void mbus_set_dtls_conversation(packet_info *pinfo, const mbus_packet_info_t *mbus_info)
{
    address meter_addr, other_addr;

    if (mbus_info->wireless) {
        // For wireless use the meter address in combination with the generic O for
        // the other device. This always matches whether the destination device
        // is known from dissection.
        const mbus_address_t *meter = NULL;
        if (mbus_is_msg_from_meter(mbus_info->cfield)) {
            meter = &mbus_info->wireless_info.link_layer_address;
        }
        else if (mbus_info->wireless_info.destination_present) {
            meter = &mbus_info->wireless_info.destination_address;
        }
        if (meter == NULL) {
            return;  // e.g. TlsToDeviceShortHeader: no meter identity in the frame
        }
        char meter_str[ITEM_LABEL_LENGTH];
        create_address_string(meter, meter_str, sizeof(meter_str));   // unprefixed

        char *meter_wmem = wmem_strdup(pinfo->pool, meter_str);
        set_address(&meter_addr, AT_STRINGZ, (int)strlen(meter_wmem) + 1, meter_wmem);
        set_address(&other_addr, AT_STRINGZ, 2, "O");
    } else {
        // For wired use the clean M and O for matching conversations.
        set_address(&meter_addr, AT_STRINGZ, 2, "M");
        set_address(&other_addr, AT_STRINGZ, 2, "O");
    }

    conversation_set_conv_addr_port_endpoints(pinfo, &meter_addr, &other_addr, CONVERSATION_NONE, 0, 0);
}
