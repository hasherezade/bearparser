cmake_minimum_required (VERSION 2.8)
project (bearcommander)

# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)
# Instruct CMake to run moc automatically when needed.
set(CMAKE_AUTOMOC ON)

find_package(Qt5Core REQUIRED)
get_target_property(QtCore_location Qt5::Core LOCATION)

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
target_link_libraries(bearcommander ${PARSER_LIB}  Qt5::Core)

