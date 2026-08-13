/* packet-wmbus-module.h
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
#include <stdint.h>

#ifndef PACKET_WMBUS_MODULE_H
#define PACKET_WMBUS_MODULE_H

#define WMBUS_MODULE_PROTOABBREV   "wmbus_module"

#define wmbus_module_message_modes_VALUE_STRING_LIST(XXX)       \
    XXX(WMBUS_MODULE_MESSAGE_MODE_M2O_MODE_C, 0, "M2O Mode C")  \
    XXX(WMBUS_MODULE_MESSAGE_MODE_M2O_MODE_T, 1, "M2O Mode T")  \
    XXX(WMBUS_MODULE_MESSAGE_MODE_O2M_MODE_C, 2, "O2M Mode C")  \
    XXX(WMBUS_MODULE_MESSAGE_MODE_O2M_MODE_T, 3, "O2M Mode T")

VALUE_STRING_ENUM(wmbus_module_message_modes);

// Added a NOFRAME variant as a temporary solution
// needed so we can handoff data from another dissector that
// removes the framing
#define wmbus_module_message_formats_VALUE_STRING_LIST(XXX)     \
    XXX(WMBUS_MODULE_MESSAGE_FORMAT_A, 0, "Format A")           \
    XXX(WMBUS_MODULE_MESSAGE_FORMAT_B, 1, "Format B")           \
    XXX(WMBUS_MODULE_MESSAGE_FORMAT_NOFRAME, 2, "Frameless")

VALUE_STRING_ENUM(wmbus_module_message_formats);

typedef struct {
    uint8_t mode;
    uint8_t format;
    uint64_t synctime; // The synchronization time of the message in microseconds
    uint32_t airtime; // The airtime of the message in microseconds
} wmbus_module_packet_t;

#endif /* PACKET_WMBUS_MODULE_H */
