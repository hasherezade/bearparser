cmake_minimum_required(VERSION 3.0)
project (bearcommander)

if(USE_QT4)
    find_package (Qt4 REQUIRED)
    include_directories( ${QT_INCLUDE_DIR} ${QT_QTCORE_INCLUDE_DIR} )
    INCLUDE( ${QT_USE_FILE} )
    ADD_DEFINITIONS( ${QT_DEFINITIONS} )
else()
    find_package(QT NAMES Qt6 Qt5 COMPONENTS Core REQUIRED)
    find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Core REQUIRED)
    get_target_property(QtCore_location Qt${QT_VERSION_MAJOR}::Core LOCATION)
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
    target_link_libraries(${PROJECT_NAME} Qt${QT_VERSION_MAJOR}::Core)
endif()

#install
INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )

