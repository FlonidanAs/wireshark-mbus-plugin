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

enum {
    PACKET_WMBUS_MESSAGE_M2O_MODE_C,
    PACKET_WMBUS_MESSAGE_M2O_MODE_T,
    PACKET_WMBUS_MESSAGE_O2M_MODE_C,
    PACKET_WMBUS_MESSAGE_O2M_MODE_T
};

enum {
    PACKET_WMBUS_MESSAGE_FORMAT_A,
    PACKET_WMBUS_MESSAGE_FORMAT_B
};

typedef struct {
    uint8_t mode;
    uint8_t format;
    uint64_t synctime; // The synchronization time of the message in microseconds
    uint32_t airtime; // The airtime of the message in microseconds
} wmbus_module_packet_t;

#endif /* PACKET_WMBUS_MODULE_H */
