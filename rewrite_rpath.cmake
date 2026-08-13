# rewrite_rpath.cmake
set(HOMEBREW_PREFIX "/opt/homebrew/opt")

# Run otool -L to get linked libraries
execute_process(
        COMMAND otool -L ${TARGET_FILE}
        OUTPUT_VARIABLE OTOOL_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Split into lines
string(REPLACE "\n" ";" OTOOL_LINES "${OTOOL_OUTPUT}")

foreach(LINE IN LISTS OTOOL_LINES)
    # Check if this line references our target prefix
    if(LINE MATCHES "${HOMEBREW_PREFIX}")
        # Extract the full library path (otool indents with a tab, strip it)
        string(REGEX MATCH "${HOMEBREW_PREFIX}[^ ]+" LIB_PATH "${LINE}")

        if(LIB_PATH)
            # Get just the filename
            get_filename_component(LIB_NAME "${LIB_PATH}" NAME)

            message(STATUS "Rewriting ${LIB_PATH} -> @rpath/${LIB_NAME}")

            execute_process(
                    COMMAND install_name_tool -change
                    "${LIB_PATH}"
                    "@rpath/${LIB_NAME}"
                    "${TARGET_FILE}"
                    RESULT_VARIABLE RESULT
            )

            if(NOT RESULT EQUAL 0)
                message(WARNING "install_name_tool failed for ${LIB_PATH}")
            endif()
        endif()
    endif()
endforeach()