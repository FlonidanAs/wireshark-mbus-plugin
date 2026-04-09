/* packet-mbus.h
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
#ifndef PACKET_MBUS_H
#define PACKET_MBUS_H

uint8_t mbus_dissect_cfield(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int* offset);

#endif /* PACKET_MBUS_H */
