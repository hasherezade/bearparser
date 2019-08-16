cmake_minimum_required(VERSION 2.8.11)
project (bearparser)

# Offer the user the choice of overriding the installation directories
set(INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(INSTALL_BIN_DIR bin CACHE PATH "Installation directory for executables")

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

include_directories (include)

set (win_hdrs
    win_hdrs/poppack.h
    win_hdrs/pshpack1.h
    win_hdrs/pshpack2.h
    win_hdrs/pshpack4.h
    win_hdrs/pshpack8.h
    win_hdrs/win_types.h
)

set (pe_hdrs
    pe/pe_formats.h
    pe/pe_undoc.h
    pe/DosHdrWrapper.h
    pe/DOSExe.h
    pe/PECore.h
    pe/PEFile.h
    pe/RichHdrWrapper.h
    pe/FileHdrWrapper.h
    pe/OptHdrWrapper.h
    pe/SectHdrsWrapper.h
    pe/DataDirWrapper.h
    pe/PENodeWrapper.h
    pe/DataDirEntryWrapper.h
    pe/ImportBaseDirWrapper.h
    pe/ImportDirWrapper.h
    pe/DelayImpDirWrapper.h
    pe/BoundImpDirWrapper.h
    pe/DebugDirWrapper.h
    pe/ExportDirWrapper.h
    pe/SecurityDirWrapper.h
    pe/TlsDirWrapper.h
    pe/LdConfigDirWrapper.h
    pe/RelocDirWrapper.h
    pe/ExceptionDirWrapper.h
    pe/ResourceDirWrapper.h
    pe/ResourceLeafWrapper.h
)

set (pe_rsrc_hdrs
    pe/rsrc/ResourcesAlbum.h
    pe/rsrc/ResourceContentFactory.h
    pe/rsrc/ResourceContentWrapper.h
    pe/rsrc/ResourceStringsWrapper.h
    pe/rsrc/ResourceVersionWrapper.h
)

set (parser_hdrs
    include/bearparser.h
    Util.h
    CustomException.h
    AbstractByteBuffer.h
    WrappedValue.h
    ByteBuffer.h
    FileBuffer.h
    Executable.h
    MappedExe.h
    ExeElementWrapper.h
    ExeNodeWrapper.h
    ExeFactory.h
    Formatter.h
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

if(USE_QT4)
    target_link_libraries (bearparser ${QT_QTCORE_LIBRARIES} )
else()
    target_link_libraries(bearparser Qt5::Core)
endif()



