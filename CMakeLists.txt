cmake_minimum_required(VERSION 3.12)
project (re-bear)

# modules:
set ( M_BEARPARSER "parser" )
set ( M_COMMANDER "commander" )

option( USE_QT5 "Use Qt4 (Qt5 by default)" OFF )

# modules paths:
set (PARSER_INC "${M_BEARPARSER}/include")
set (PARSER_DIR "${CMAKE_SOURCE_DIR}/${M_BEARPARSER}" CACHE PATH "BearParser main path")
set (COMMANDER_DIR "${CMAKE_SOURCE_DIR}/${M_COMMANDER}" CACHE PATH "BearCommander main path")

# Add sub-directories
#
# libs

add_subdirectory (${M_BEARPARSER})
include_directories(${PARSER_INC})

set (PARSER_LIB bearparser CACHE FILE "BearParser library path")

# executables
add_subdirectory(commander)

# dependencies
add_dependencies(bearcommander bearparser)

