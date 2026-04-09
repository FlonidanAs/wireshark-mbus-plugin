# CMakeLists.txt
#
# Copyright 2026, Martin B. Petersen <mbp@flonidan.dk>
# Copyright 2026, Kenneth Soerensen <ks@flonidan.dk>
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(mbus 0 0 1 0)

set(DISSECTOR_SRC
	packet-mbus-common.c
	packet-mbus.c
	packet-mbus-ell.c
	packet-mbus-afl.c
	packet-mbus-tpl.c
	packet-mbus-apl.c
	packet-mbus-dsmr6.c
)

set(DISSECTOR_SUPPORT_SRC
	packet-mbus-security.c
	packet-wmbus.c
	packet-wmbus-module.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

set_source_files_properties(
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

add_wireshark_plugin_library(mbus epan)

target_link_libraries(mbus epan ${GCRYPT_LIBRARIES})

install_plugin(mbus epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  mbus
	SWITCHES
	  --group dissectors-prohibited
	  --group dissectors-restricted
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_SUPPORT_SRC}
	  ${DISSECTOR_HEADERS}
)

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
