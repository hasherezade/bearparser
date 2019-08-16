cmake_minimum_required(VERSION 2.8.11)
project (bearcommander)

if(USE_QT4)
    add_compile_definitions(WITH_QT4)
    find_package (Qt4 REQUIRED)
    include_directories( ${QT_INCLUDE_DIR} ${QT_QTCORE_INCLUDE_DIR} )
    INCLUDE( ${QT_USE_FILE} )
    ADD_DEFINITIONS( ${QT_DEFINITIONS} )
else()
    add_compile_definitions(WITH_QT5)
    find_package(Qt5Core REQUIRED)
    get_target_property(QtCore_location Qt5::Core LOCATION)
endif()

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
target_link_libraries(bearcommander ${PARSER_LIB})

if(USE_QT4)
    target_link_libraries (bearcommander ${QT_QTCORE_LIBRARIES} )
else()
    target_link_libraries(bearcommander Qt5::Core)
endif()

