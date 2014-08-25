#pragma once

#include "pe_formats.h"
#include "PECore.h"

#include "DOSExe.h"
#include "FileHdrWrapper.h"
#include "OptHdrWrapper.h"
#include "SectHdrsWrapper.h"
#include "DataDirWrapper.h"

#include "ImportDirWrapper.h"
#include "DelayImpDirWrapper.h"
#include "BoundImpDirWrapper.h"
#include "DebugDirWrapper.h"
#include "ExportDirWrapper.h"
#include "SecurityDirWrapper.h"
#include "TlsDirWrapper.h"
#include "LdConfigDirWrapper.h"
#include "RelocDirWrapper.h"
#include "ExceptionDirWrapper.h"
#include "ResourceDirWrapper.h"

#include "rsrc/ResourcesAlbum.h"

class PEFile;

class PEFileBuilder: public ExeBuilder {
public:
    PEFileBuilder() : ExeBuilder() {}
    virtual bool signatureMatches(AbstractByteBuffer *buf);
    virtual Executable* build(AbstractByteBuffer *buf);
    QString typeName() { return "PE"; }
};

//-------------------------------------------------------------

class PEFile : public DOSExe
{
public:
    enum WRAPPERS {
        WR_NONE = MappedExe::WR_NONE,
        WR_DOS_HDR = DOSExe::WR_DOS_HDR,
        WR_FILE_HDR,
        WR_OPTIONAL_HDR,
        WR_DATADIR,
        WR_SECTIONS,
        WR_DIR_ENTRY,
        WR_DIR_ENTRY_END = WR_DIR_ENTRY + pe::DIR_ENTRIES_COUNT,
        COUNT_WRAPPERS
    };

    PEFile(AbstractByteBuffer *v_buf);
    virtual ~PEFile() { TRACE(); clearWrappers(); delete album; }

    virtual void clearWrappers();

    exe_bits getHdrBitMode();
    virtual exe_bits getBitMode() { return getHdrBitMode(); }
    Executable::addr_type detectAddrType(offset_t addr, Executable::addr_type hintType) { return Executable::RAW; }

    virtual bufsize_t getMappedSize(Executable::addr_type aType);
    virtual bufsize_t getAlignment(Executable::addr_type aType);
    virtual offset_t getImageBase();
    virtual offset_t getEntryPoint();

    // returns INVALID_ADDR if failed
    virtual offset_t fileAddrToRva(offset_t raw, bool getClosestIfInCave = false);

    //virtual offset_t VaToRva(offset_t va, bool autodetect = true) const;
    virtual offset_t VaToFileAddr(offset_t rva, bool getClosestIfInCave = false);
    virtual offset_t rvaToFileAddr(offset_t rva, bool getClosestIfInCave = false);
    virtual offset_t rvaToVa(offset_t rva);

    virtual offset_t getWrapperRawOffset(int wrapperId);

    offset_t peHdrOffset();
    offset_t peNtHdrOffset();
    offset_t peOptHdrOffset();
    offset_t peDataDirOffset();
    offset_t secHdrsOffset();

    pe::IMAGE_DATA_DIRECTORY* getDataDirectory();

    size_t hdrSectionsNum();

    SectionHdrWrapper* getSecHdr(size_t secNum)
    {
        return (sects == NULL) ? NULL : sects->getSecHdr(secNum);
    }

    SectionHdrWrapper* getSecHdrAtOffset(offset_t offset, Executable::addr_type aType, bool roundup, bool verbose = false)
    {
        return (sects == NULL) ? NULL : sects->getSecHdrAtOffset(offset, aType, roundup, verbose);
    }
    ResourcesAlbum* getResourcesAlbum() const { return this->album; }
    ResourcesContainer*  getResourcesOfType(pe::resource_type typeId) { return (this->album == NULL) ? NULL : album->getResourcesOfType(typeId); }

protected:
    PECore core;

    virtual void wrap(AbstractByteBuffer *v_buf);
    //---
    bool setHdrSectionsNum(size_t newNum);

    FileHdrWrapper *fHdr;
    OptHdrWrapper *optHdr;
    SectHdrsWrapper *sects;

    ResourcesAlbum *album;
    DataDirEntryWrapper* dataDirEntries[pe::DIR_ENTRIES_COUNT];

friend class SectHdrsWrapper;
};


