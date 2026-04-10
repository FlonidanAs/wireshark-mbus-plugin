/* packet-mbus-plugin.c
 * Plugin registration for out-of-tree plugins
 *
 * Copyright 2026, Hugo Trippaers <htrippaers@schubergphilis.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"
#include <wsutil/plugins.h>

#include "epan/proto.h"

#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION "0.0.1"
#endif

WS_DLL_PUBLIC_DEF const char plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);
WS_DLL_PUBLIC uint32_t plugin_describe(void);

void proto_register_mbus(void);
void proto_reg_handoff_mbus(void);

void proto_register_mbus_afl(void);
void proto_reg_handoff_mbus_afl(void);

void proto_register_mbus_apl(void);
void proto_reg_handoff_mbus_apl(void);

void proto_register_mbus_dsmr6(void);
void proto_reg_handoff_mbus_dsmr6(void);

void proto_register_mbus_ell(void);
void proto_reg_handoff_mbus_ell(void);

void proto_register_mbus_tpl(void);
void proto_reg_handoff_mbus_tpl(void);

void proto_register_wmbus(void);
void proto_reg_handoff_wmbus(void);

void proto_register_wmbus_module(void);
void proto_reg_handoff_wmbus_module(void);

void
plugin_register(void)
{
    ws_info("Registering (w)mbus protocol dissectors");

    static proto_plugin plug_mbus;
    plug_mbus.register_protoinfo = proto_register_mbus;
    plug_mbus.register_handoff = proto_reg_handoff_mbus;
    proto_register_plugin(&plug_mbus);

    static proto_plugin plug_mbus_afl;
    plug_mbus_afl.register_protoinfo = proto_register_mbus_afl;
    plug_mbus_afl.register_handoff = proto_reg_handoff_mbus_afl;
    proto_register_plugin(&plug_mbus_afl);

    static proto_plugin plug_mbus_apl;
    plug_mbus_apl.register_protoinfo = proto_register_mbus_apl;
    plug_mbus_apl.register_handoff = proto_reg_handoff_mbus_apl;
    proto_register_plugin(&plug_mbus_apl);

    static proto_plugin plug_mbus_dsmr6;
    plug_mbus_dsmr6.register_protoinfo = proto_register_mbus_dsmr6;
    plug_mbus_dsmr6.register_handoff = proto_reg_handoff_mbus_dsmr6;
    proto_register_plugin(&plug_mbus_dsmr6);

    static proto_plugin plug_mbus_ell;
    plug_mbus_ell.register_protoinfo = proto_register_mbus_ell;
    plug_mbus_ell.register_handoff = proto_reg_handoff_mbus_ell;
    proto_register_plugin(&plug_mbus_ell);

    static proto_plugin plug_mbus_tpl;
    plug_mbus_tpl.register_protoinfo = proto_register_mbus_tpl;
    plug_mbus_tpl.register_handoff = proto_reg_handoff_mbus_tpl;
    proto_register_plugin(&plug_mbus_tpl);

    static proto_plugin plug_wmbus;
    plug_wmbus.register_protoinfo = proto_register_wmbus;
    plug_wmbus.register_handoff = proto_reg_handoff_wmbus;
    proto_register_plugin(&plug_wmbus);

    static proto_plugin plug_wmbus_module;
    plug_wmbus_module.register_protoinfo = proto_register_wmbus_module;
    plug_wmbus_module.register_handoff = proto_reg_handoff_wmbus_module;
    proto_register_plugin(&plug_wmbus_module);
}

uint32_t
plugin_describe(void)
{
    return WS_PLUGIN_DESC_DISSECTOR;
}