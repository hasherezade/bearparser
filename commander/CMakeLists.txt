cmake_minimum_required (VERSION 2.8)
project (bearcommander)

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

