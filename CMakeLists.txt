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

cmake_minimum_required(VERSION 4.2)

project(WirelessMBUSPlugin)

find_package(Wireshark CONFIG REQUIRED)

find_package(PkgConfig)

pkg_check_modules(GpgError REQUIRED
		gpg-error)

pkg_check_modules(Gcrypt REQUIRED
		libgcrypt
)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
			CACHE PATH "Installation prefix" FORCE
	)
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
	message(WARNING "Wireshark was compiled without support for plugins")
endif()

set(DISSECTOR_SRC
	packet-mbus-afl.c
	packet-mbus-apl.c
	packet-mbus-common.c
	packet-mbus-dlms-cosem.c
	packet-mbus-dsmr6.c
	packet-mbus-ell.c
	packet-mbus-security.c
	packet-mbus-tpl.c
	packet-mbus.c
	packet-wmbus-module.c
	packet-wmbus.c
)

set_source_files_properties(
	${DISSECTOR_SRC}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)


add_library(mbus MODULE
		 packet-mbus-plugin.c
		${DISSECTOR_SRC}
		${DISSECTOR_SUPPORT_SRC}
)

target_link_libraries(mbus
		epan
		m
		${Gcrypt_LIBRARIES}
)

target_include_directories(mbus PUBLIC
		${GpgError_INCLUDE_DIRS}
)

target_link_directories(mbus PRIVATE
		${Gcrypt_LIBRARY_DIRS}
)


if(APPLE)
	add_custom_command(TARGET mbus POST_BUILD
			COMMAND ${CMAKE_COMMAND}
			-DTARGET_FILE=$<TARGET_FILE:mbus>
			-P ${CMAKE_CURRENT_SOURCE_DIR}/rewrite_rpath.cmake
	)
endif ()

add_custom_command(TARGET mbus POST_BUILD
		COMMAND cp
		$<TARGET_FILE:mbus>
		${CMAKE_CURRENT_BINARY_DIR}/mbus-dissector.so
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
