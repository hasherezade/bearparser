cmake_minimum_required(VERSION 3.12)
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

add_executable (${PROJECT_NAME} ${imps_hdrs} ${imps_srcs} )
target_link_libraries(${PROJECT_NAME} ${PARSER_LIB})

if(USE_QT4)
    target_link_libraries (${PROJECT_NAME} ${QT_QTCORE_LIBRARIES} )
else()
    target_link_libraries(${PROJECT_NAME} Qt5::Core)
endif()

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

