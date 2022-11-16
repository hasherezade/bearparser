cmake_minimum_required(VERSION 3.0)
project (bearparser)

# Offer the user the choice of overriding the installation directories
set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for executables")

if(USE_QT4)
    find_package (Qt4 REQUIRED)
    include_directories( ${QT_INCLUDE_DIR} ${QT_QTCORE_INCLUDE_DIR} )
    INCLUDE( ${QT_USE_FILE} )
    ADD_DEFINITIONS( ${QT_DEFINITIONS} )
else()
    find_package(Qt5Core REQUIRED)
    get_target_property(QtCore_location Qt5::Core LOCATION)
endif()

include_directories (include/bearparser)

set (win_hdrs
    include/bearparser/win_hdrs/poppack.h
    include/bearparser/win_hdrs/pshpack1.h
    include/bearparser/win_hdrs/pshpack2.h
    include/bearparser/win_hdrs/pshpack4.h
    include/bearparser/win_hdrs/pshpack8.h
    include/bearparser/win_hdrs/win_types.h
)

set (pe_hdrs
    include/bearparser/pe/pe_formats.h
    include/bearparser/pe/pe_undoc.h
    include/bearparser/pe/DosHdrWrapper.h
    include/bearparser/pe/DOSExe.h
    include/bearparser/pe/PECore.h
    include/bearparser/pe/PEFile.h
    include/bearparser/pe/RichHdrWrapper.h
    include/bearparser/pe/FileHdrWrapper.h
    include/bearparser/pe/OptHdrWrapper.h
    include/bearparser/pe/SectHdrsWrapper.h
    include/bearparser/pe/DataDirWrapper.h
    include/bearparser/pe/PENodeWrapper.h
    include/bearparser/pe/DataDirEntryWrapper.h
    include/bearparser/pe/ImportBaseDirWrapper.h
    include/bearparser/pe/ImportDirWrapper.h
    include/bearparser/pe/DelayImpDirWrapper.h
    include/bearparser/pe/BoundImpDirWrapper.h
    include/bearparser/pe/DebugDirWrapper.h
    include/bearparser/pe/ExportDirWrapper.h
    include/bearparser/pe/SecurityDirWrapper.h
    include/bearparser/pe/TlsDirWrapper.h
    include/bearparser/pe/LdConfigDirWrapper.h
    include/bearparser/pe/RelocDirWrapper.h
    include/bearparser/pe/ExceptionDirWrapper.h
    include/bearparser/pe/ResourceDirWrapper.h
    include/bearparser/pe/ResourceLeafWrapper.h
    include/bearparser/pe/ClrDirWrapper.h
)

set (pe_rsrc_hdrs
    include/bearparser/pe/rsrc/ResourcesAlbum.h
    include/bearparser/pe/rsrc/ResourceContentFactory.h
    include/bearparser/pe/rsrc/ResourceContentWrapper.h
    include/bearparser/pe/rsrc/ResourceStringsWrapper.h
    include/bearparser/pe/rsrc/ResourceVersionWrapper.h
)

set (parser_hdrs
    include/bearparser/bearparser.h
    include/bearparser/Util.h
    include/bearparser/CustomException.h
    include/bearparser/AbstractByteBuffer.h
    include/bearparser/WrappedValue.h
    include/bearparser/ByteBuffer.h
    include/bearparser/FileBuffer.h
    include/bearparser/Executable.h
    include/bearparser/MappedExe.h
    include/bearparser/ExeElementWrapper.h
    include/bearparser/ExeNodeWrapper.h
    include/bearparser/ExeFactory.h
    include/bearparser/Formatter.h
)

set (pe_srcs
    pe/DosHdrWrapper.cpp
    pe/DOSExe.cpp
    pe/PECore.cpp
    pe/PEFile.cpp
    pe/RichHdrWrapper.cpp
    pe/FileHdrWrapper.cpp
    pe/OptHdrWrapper.cpp
    pe/SectHdrsWrapper.cpp
    pe/DataDirWrapper.cpp
    pe/PENodeWrapper.cpp
    pe/DataDirEntryWrapper.cpp
    pe/ImportBaseDirWrapper.cpp
    pe/ImportDirWrapper.cpp
    pe/DelayImpDirWrapper.cpp
    pe/BoundImpDirWrapper.cpp
    pe/DebugDirWrapper.cpp
    pe/ExportDirWrapper.cpp
    pe/SecurityDirWrapper.cpp
    pe/TlsDirWrapper.cpp
    pe/LdConfigDirWrapper.cpp
    pe/RelocDirWrapper.cpp
    pe/ExceptionDirWrapper.cpp
    pe/ResourceDirWrapper.cpp
    pe/ClrDirWrapper.cpp
)

set (pe_rsrc_srcs
    pe/rsrc/ResourcesAlbum.cpp
    pe/rsrc/ResourceContentFactory.cpp
    pe/rsrc/ResourceContentWrapper.cpp
    pe/rsrc/ResourceStringsWrapper.cpp
    pe/rsrc/ResourceVersionWrapper.cpp
)

set (parser_srcs
    Util.cpp
    AbstractByteBuffer.cpp
    WrappedValue.cpp
    ByteBuffer.cpp
    FileBuffer.cpp
    Executable.cpp
    MappedExe.cpp
    ExeElementWrapper.cpp
    ExeNodeWrapper.cpp
    ExeFactory.cpp
    Formatter.cpp
)

set (parser_srcs
    ${parser_srcs}
    ${pe_srcs}
    ${pe_rsrc_srcs}
)

set (parser_hdrs
    ${win_hdrs}
    ${parser_hdrs}
    ${pe_hdrs}
    ${pe_rsrc_hdrs}
)

SOURCE_GROUP("Header Files\\win_hdrs" FILES ${win_hdrs} )

SOURCE_GROUP("Source Files\\pe" FILES ${pe_srcs} )
SOURCE_GROUP("Header Files\\pe" FILES ${pe_hdrs} )
SOURCE_GROUP("Source Files\\pe\\rsrc" FILES ${pe_rsrc_srcs} )
SOURCE_GROUP("Header Files\\pe\\rsrc" FILES ${pe_rsrc_hdrs} )

add_library ( bearparser STATIC ${parser_hdrs} ${parser_srcs} )

target_include_directories(bearparser PUBLIC "${CMAKE_CURRENT_LIST_DIR}/include/")

if(USE_QT4)
    target_link_libraries (bearparser ${QT_QTCORE_LIBRARIES} )
else()
    target_link_libraries(bearparser Qt5::Core)
endif()


