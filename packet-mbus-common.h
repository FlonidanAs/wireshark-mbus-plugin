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
#include <epan/packet.h>
#include "packet-mbus-security.h"

#ifndef PACKET_MBUS_COMMON_H
#define PACKET_MBUS_COMMON_H

#define MBUS_PROTOABBREV "mbus"
#define MBUS_PROTOABBREV_ELL "mbus_ell"
#define MBUS_PROTOABBREV_AFL "mbus_afl"
#define MBUS_PROTOABBREV_TPL "mbus_tpl"
#define MBUS_PROTOABBREV_APL "mbus_apl"
#define MBUS_PROTOABBREV_DLMS "mbus_dlms"

typedef struct {
    uint8_t cfield;
    bool wireless;
    struct {
        uint8_t address;
    } wired_info;
    // The wireless info which is needed is stored in the security info struct
    mbus_secure_ctx_t security_info;
    uint8_t ciField;
} mbus_packet_info_t;

/* MBus C Fields */
#define MBUS_C_FIELD_FUNC_MASK                          0x0F
#define MBUS_C_FIELD_FCV_DFC_MASK                       0x10
#define MBUS_C_FIELD_FCB_ACD_MASK                       0x20
#define MBUS_C_FIELD_DIR_MASK                           0x40

/* MBus CI Fields*/
#define mbus_ci_field_names_VALUE_STRING_LIST(XXX) \
    XXX(DLMSBasedApplicationMinimumAllowed,             0x00, "DLMS-based application minimum allowed") \
    XXX(DLMSBasedApplicationMaximumAllowed,             0x1F, "DLMS-based application maximum allowed") \
    /*(Reserved, 0x20-0x4F, "Reserved") */ \
    XXX(ApplicationResetOrSelectToDeviceNoHeader,       0x50, "Application Reset Or Select to Device") \
    XXX(DataSend,                                       0x51, "Data Send") \
    XXX(SelectionOfDevice,                              0x52, "Selection Of Device") \
    XXX(ApplicationResetOrSelectToDeviceLongHeader,     0x53, "Application Reset Or Select to Device") \
    /*(Reserved, 0x54-0x59, "Reserved") */ \
    XXX(CommandToDeviceShortHeader,                     0x5A, "Command To Device") \
    XXX(CommandToDeviceLongHeader,                      0x5B, "Command To Device") \
    XXX(SynchroniseAction,                              0x5C, "Synchronise Action") \
    XXX(TlsToDeviceShortHeader,                         0x5E, "TLS To Device") \
    XXX(TlsToDeviceLongHeader,                          0x5F, "TLS To Device") \
    XXX(CommandToDeviceDLMSLongHeader,                  0x60, "Command To Device DLMS") \
    XXX(CommandToDeviceDLMSShortHeader,                 0x61, "Command To Device DLMS") \
    /*(Reserved, 0x62-0x63, "Reserved") */ \
    XXX(CommandToDeviceOBISTypeLongHeader,              0x64, "Command To Device OBIS type") \
    XXX(CommandToDeviceOBISTypeShortHeader,             0x65, "Command To Device OBIS type") \
    /*(Reserved, 0x66-0x68, "Reserved") */ \
    XXX(ResponseFromDeviceFormatFrameNoHeader,          0x69, "Response From Device Format Frame") \
    XXX(ResponseFromDeviceFormatFrameShortHeader,       0x6A, "Response From Device Format Frame") \
    XXX(ResponseFromDeviceFormatFrameLongHeader,        0x6B, "Response From Device Format Frame") \
    XXX(TimeSyncToDeviceLongHeader_1,                   0x6C, "TimeSync To Device") \
    XXX(TimeSyncToDeviceLongHeader_2,                   0x6D, "TimeSync To Device") \
    XXX(ApplicationErrorFromDeviceShortHeader,          0x6E, "Application Error From Device") \
    XXX(ApplicationErrorFromDeviceLongHeader,           0x6F, "Application Error From Device") \
    XXX(ApplicationErrorFromDeviceNoHeader,             0x70, "Application Error From Device") \
    XXX(AlarmFromDeviceNoHeader,                        0x71, "Alarm From Device") \
    XXX(ResponseFromDeviceLongHeader,                   0x72, "Response From Device") \
    XXX(ResponseFromDeviceCompactFrameLongHeader,       0x73, "Response From Device Compact Frame") \
    XXX(AlarmFromDeviceShortHeader,                     0x74, "Alarm From Device") \
    XXX(AlarmFromDeviceLongHeader,                      0x75, "Alarm From Device") \
    /*(Reserved, 0x76-0x77, "Reserved") */ \
    XXX(ResponseFromDeviceNoHeader,                     0x78, "Response From Device") \
    XXX(ResponseFromDeviceCompactFrameNoHeader,         0x79, "Response From Device Compact Frame") \
    XXX(ResponseFromDeviceShortHeader,                  0x7A, "Response From Device") \
    XXX(ResponseFromDeviceCompactFrameShortHeader,      0x7B, "Response From Device Compact Frame") \
    XXX(ResponseFromDeviceDLMSLongHeader,               0x7C, "Response From Device DLMS") \
    XXX(ResponseFromDeviceDLMSShortHeader,              0x7D, "Response From Device DLMS") \
    XXX(ResponseFromDeviceOBISLongHeader,               0x7E, "Response From Device OBIS") \
    XXX(ResponseFromDeviceOBISShortHeader,              0x7F, "Response From Device OBIS") \
    XXX(TransportLayerToDeviceLongHeader,               0x80, "Transport Layer To Device") \
    XXX(NetworkLayerData,                               0x81, "Network Layer Data") \
    XXX(ReservedForNetworkManagementData,               0x82, "Reserved For Network Management Data") \
    XXX(NetworkManagementData,                          0x83, "Network Management Data") \
    XXX(TransportLayerToDeviceCompactFrameLongHeader,   0x84, "Transport Layer To Device Compact Frame") \
    XXX(TransportLayerToDeviceFormatFrameLongHeader,    0x85, "Transport Layer To Device Format Frame") \
    /*(Reserved, 0x86-0x88, "Reserved") */ \
    XXX(ReservedForNetworkManagementDataFromDevice,     0x89, "Reserved For Network Management Data From Device") \
    XXX(TransportLayerFromDeviceShortHeader,            0x8A, "Transport Layer From Device") \
    XXX(TransportLayerFromDeviceLongHeader,             0x8B, "Transport Layer From Device") \
    XXX(ExtendedLinkLayer1,                             0x8C, "Extended Link Layer 1") \
    XXX(ExtendedLinkLayer2,                             0x8D, "Extended Link Layer 2") \
    XXX(ExtendedLinkLayer3,                             0x8E, "Extended Link Layer 3") \
    XXX(ExtendedLinkLayer4,                             0x8F, "Extended Link Layer 4") \
    XXX(AuthenticationFragmentationLayer,               0x90, "Authentication Fragmentation Layer") \
    /*(Reserved, 0x91-0x9D, "Reserved") */ \
    XXX(TlsFromDeviceShortHeader,                       0x9E, "TLS From Device") \
    XXX(TlsFromDeviceLongHeader,                        0x9F, "TLS From Device") \
    /*(ManufacturerSpecific, 0xA0-0xB7, "Manufacturer Specific") */ \
    XXX(SetBaudRateTo8192Baud,                          0xB6, "Set BaudRate To 8192 Baud") \
    XXX(SetBaudRateTo10922Baud,                         0xB7, "Set BaudRate To 10922 Baud") \
    XXX(SetBaudRateTo300Baud,                           0xB8, "Set BaudRate To 300 Baud") \
    XXX(SetBaudRateTo600Baud,                           0xB9, "Set BaudRate To 600 Baud") \
    XXX(SetBaudRateTo1200Baud,                          0xBA, "Set BaudRate To 1200 Baud") \
    XXX(SetBaudRateTo2400Baud,                          0xBB, "Set BaudRate To 2400 Baud") \
    XXX(SetBaudRateTo4800Baud,                          0xBC, "Set BaudRate To 4800 Baud") \
    XXX(SetBaudRateTo9600Baud,                          0xBD, "Set BaudRate To 9600 Baud") \
    XXX(SetBaudRateTo19200Baud,                         0xBE, "Set BaudRate To 19200 Baud") \
    XXX(SetBaudRateTo38400Baud,                         0xBF, "Set BaudRate To 38400 Baud") \
    XXX(ImageTransferCommandLongHeader,                 0xC0, "Image Transfer Command Long Header") \
    XXX(ImageTransferResponseShortHeader,               0xC1, "Image Transfer Response Short Header") \
    XXX(ImageTransferResponseLongHeader,                0xC2, "Image Transfer Response Long Header")
    /*(Reserved, 0xC0-0xFF, "Reserved") */

VALUE_STRING_ENUM(mbus_ci_field_names);
extern value_string_ext mbus_ci_field_names_ext;

bool mbus_is_dlms_ci_field(uint8_t ciField);
bool mbus_is_ell_ci_field(uint8_t ciField);
bool mbus_is_afl_ci_field(uint8_t ciField);
bool mbus_is_compact_frame_ci_field(uint8_t ciField);
bool mbus_is_image_transfer_ci_field(uint8_t ciField);
bool mbus_is_tls_ci_field(uint8_t ciField);

void mbus_manufacturer_id_to_string(char *s, size_t buffer_size, uint16_t value);
void mbus_decode_manufacturer_id(char *s, uint16_t value);

void mbus_set_address_and_port_info(packet_info *pinfo, uint8_t cfield, const char* address);

#endif /* PACKET_MBUS_COMMON_H */

