cmake_minimum_required (VERSION 2.8)
project (re-bear)

# modules:
set ( M_BEARPARSER "parser" )
set ( M_COMMANDER "commander" )

# modules paths:
set (PARSER_DIR "${CMAKE_SOURCE_DIR}/${M_BEARPARSER}" CACHE PATH "BearParser main path")
set (COMMANDER_DIR "${CMAKE_SOURCE_DIR}/${M_COMMANDER}" CACHE PATH "BearCommander main path")

# Add sub-directories
#
# libs
add_subdirectory (parser)
get_property (parser_location TARGET bearparser PROPERTY LOCATION)
set (PARSER_LIB ${parser_location} CACHE FILE "BearParser library path")

# executables
add_subdirectory(commander)

# dependencies
add_dependencies(bearcommander bearparser)

