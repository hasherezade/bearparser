cmake_minimum_required (VERSION 2.8)
project (bearcommander)

# Offer the user the choice of overriding the installation directories
set (INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set (INSTALL_BIN_DIR bin CACHE PATH "Installation directory for executables")

message (STATUS "parser_dir='${PARSER_DIR}'")
message (STATUS "parser_lib='${PARSER_LIB}'")

find_package (Qt4 REQUIRED)
include_directories ( ${PARSER_DIR} ${QT_INCLUDE_DIR} ${QT_QTCORE_INCLUDE_DIR} )

set (imps_srcs
    main.cpp
    Commander.cpp
    ExeCommander.cpp
    PECommander.cpp
)

set (imps_hdrs
    Commander.h
    ExeCommander.h
    PECommander.h
)

add_executable (bearcommander ${imps_hdrs} ${imps_srcs} )
target_link_libraries (bearcommander ${PARSER_LIB} ${QT_QTCORE_LIBRARIES} )

INCLUDE (${QT_USE_FILE})
ADD_DEFINITIONS (${QT_DEFINITIONS})

