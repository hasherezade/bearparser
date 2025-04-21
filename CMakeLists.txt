cmake_minimum_required(VERSION 3.10)
project (re-bear)

option(CMD_BUILD_TESTING "Enable testing for bearcommander" ON)

# modules:
set ( M_BEARPARSER "parser" )
set ( M_BEARCOMMANDER "commander" )

option(USE_QT4 "Use Qt4" OFF )
option(USE_QT5 "Use Qt5" OFF )

# modules paths:
set (BEARPARSER_INC "${M_BEARPARSER}/include")

set (BEARPARSER_DIR "${CMAKE_SOURCE_DIR}/${M_BEARPARSER}" CACHE PATH "BearParser main path")
set (COMMANDER_DIR "${CMAKE_SOURCE_DIR}/${M_BEARCOMMANDER}" CACHE PATH "BearCommander main path")

# Add bearparser includes:
include_directories( ${BEARPARSER_INC} )

# Add sub-directories
#
# libs

add_subdirectory ( ${M_BEARPARSER} )
set (PARSER_LIB bearparser CACHE PATH "BearParser library path")

# executables
add_subdirectory( ${M_BEARCOMMANDER} )

# dependencies
add_dependencies(bearcommander bearparser)

# Setup testing
if(CMD_BUILD_TESTING)
	enable_testing()
	
	# 0) does the application run
	add_test (TestRuns ${CMAKE_BINARY_DIR}/bearcommander)
	set_tests_properties(TestRuns PROPERTIES PASS_REGULAR_EXPRESSION "Bearparser")
	IF (NOT WIN32)
		# 1) external tests
		add_test (TestExternal ${CMAKE_SOURCE_DIR}/test.sh ${CMAKE_SOURCE_DIR})
		set_tests_properties(TestExternal PROPERTIES PASS_REGULAR_EXPRESSION "All passed")
	ENDIF()
endif()


