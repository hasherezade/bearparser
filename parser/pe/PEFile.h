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

class PEFile : public MappedExe
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
    //---
    // inherited from Executable:
    //
    virtual void wrap();

    // FileAddr <-> RVA
    virtual offset_t rawToRva(offset_t raw);
    virtual offset_t rvaToRaw(offset_t rva);

    virtual bufsize_t getMappedSize(Executable::addr_type aType);
    virtual bufsize_t getAlignment(Executable::addr_type aType){ return core.getAlignment(aType); }
    virtual offset_t getImageBase() { return core.getImageBase(); }
    virtual offset_t getEntryPoint(); // returns INVALID_ADDR if failed

    virtual exe_bits getBitMode() { return getHdrBitMode(); }
    //---
    // PEFile only:
    offset_t peHdrOffset() { return core.peFileHdrOffset(); }
    offset_t peNtHdrOffset() { return core.peSignatureOffset(); }
    offset_t peOptHdrOffset() { return core.peOptHdrOffset(); }
    offset_t secHdrsOffset() { return core.secHdrsOffset(); }

    ResourcesAlbum* getResourcesAlbum() const { return this->album; }

    pe::IMAGE_DATA_DIRECTORY* getDataDirectory();
    offset_t peDataDirOffset();

    size_t hdrSectionsNum();
    size_t getSectionsCount(bool useMapped = true);
    exe_bits getHdrBitMode() { return core.getHdrBitMode(); }

    SectionHdrWrapper* getSecHdr(size_t secNum)
    {
        return (sects == NULL) ? NULL : sects->getSecHdr(secNum);
    }

    SectionHdrWrapper* getSecHdrAtOffset(offset_t offset, Executable::addr_type aType, bool roundup, bool verbose = false)
    {
        return (sects == NULL) ? NULL : sects->getSecHdrAtOffset(offset, aType, roundup, verbose);
    }

    ResourcesContainer*  getResourcesOfType(pe::resource_type typeId)
    {
        return (this->album == NULL) ? NULL : album->getResourcesOfType(typeId);
    }
    DataDirEntryWrapper* getDataDirEntry(pe::dir_entry eType);
    BufferView* createSectionView(size_t secNum);
    //---
    //modifications:
    bool setEntryPoint(offset_t entry, Executable::addr_type aType);
    bool moveDataDirEntry(pe::dir_entry id, offset_t newOffset, Executable::addr_type addType = Executable::RAW); //throws CustomException

    SectionHdrWrapper* getLastSection();
    SectionHdrWrapper* addNewSection(QString name, bufsize_t size, DWORD characteristics = 0xE0000000);
    SectionHdrWrapper* extendLastSection(bufsize_t addedSize);


protected:
    virtual void clearWrappers();
    virtual void wrap(AbstractByteBuffer *v_buf);

    void initDirEntries();
    PECore core;
    //---
    //modifications:
    bool setHdrSectionsNum(size_t newNum);
    bool setVitualSize(bufsize_t newSize);

    DosHdrWrapper *dosHdrWrapper;

    FileHdrWrapper *fHdr;
    OptHdrWrapper *optHdr;
    SectHdrsWrapper *sects;

    ResourcesAlbum *album;
    DataDirEntryWrapper* dataDirEntries[pe::DIR_ENTRIES_COUNT];

friend class SectHdrsWrapper;
};


