/* packet-mbus-security.h
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
#ifndef PACKET_MBUS_SECURITY_H
#define PACKET_MBUS_SECURITY_H

#define MBUS_CONFIG_MODE_MASK           0x1F00u
#define MBUS_CONFIG_MODE_SHIFT          8u

#define MBUS_CONFIG_M9_KEY_ID_MASK                     0x000Fu //!< No information (reserved?)
#define MBUS_CONFIG_M9_KEY_ID_SHIFT                    0u
#define MBUS_CONFIG_M9_KDF_SELECTION_MASK              0x0030u //!< No information (reserved?)
#define MBUS_CONFIG_M9_KDF_SELECTION_SHIFT             4u
#define MBUS_CONFIG_M9_LEN_E_BIT_MASK                  0x0040u //!< 0 = Length[E] is one byte, 1 = Length[E] is two bytes
#define MBUS_CONFIG_M9_LEN_E_BIT_SHIFT                 6u
#define MBUS_CONFIG_M9_LEN_U_BIT_MASK                  0x0080u //!< 0 = Length[U] is one byte, 1 = Length[U] is two bytes
#define MBUS_CONFIG_M9_LEN_U_BIT_SHIFT                 7u
#define MBUS_CONFIG_M9_AUTHENTICATION_TAG_SIZE_MASK    0x2000u //!< 0 = no tag, 1 = 12 byte tag
#define MBUS_CONFIG_M9_AUTHENTICATION_TAG_SIZE_SHIFT   13u

typedef struct {
    uint16_t configField;
    uint8_t configFieldExtension;
    bool fields_present;
    uint32_t identification_number;
    uint16_t manufacturer;
    uint8_t version;
    uint8_t device;
} mbus_secure_ctx_t;

/* Init routine for the Security dissectors. */
void mbus_security_register(module_t *mbus_prefs, int proto);

/* Security Dissector Routine. */
tvbuff_t* dissect_mbus_secure(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree, int offset,
                              const mbus_secure_ctx_t* mbus_secure_ctx);

#endif /* PACKET_MBUS_SECURITY_H */
