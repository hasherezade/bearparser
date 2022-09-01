#pragma once

#include "pe_formats.h"
#include "PECore.h"

#include "DOSExe.h"
#include "RichHdrWrapper.h"
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
#include "ClrDirWrapper.h"

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
        WR_RICH_HDR,
        WR_FILE_HDR,
        WR_OPTIONAL_HDR,
        WR_DATADIR,
        WR_SECTIONS,
        WR_DIR_ENTRY,
        WR_DIR_ENTRY_END = WR_DIR_ENTRY + pe::DIR_ENTRIES_COUNT,
        COUNT_WRAPPERS
    };

    static long computeChecksum(BYTE *buffer, size_t bufferSize, size_t checksumOffset);

    PEFile(AbstractByteBuffer *v_buf);
    virtual ~PEFile() { clearWrappers(); delete album; }
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
    virtual offset_t getEntryPoint(Executable::addr_type addrType = Executable::RVA); // returns INVALID_ADDR if failed

    virtual exe_bits getBitMode() { return getHdrBitMode(); }
    //---
    // PEFile only:
    offset_t peHdrOffset() { return core.peFileHdrOffset(); }
    offset_t peNtHdrOffset() { return core.peSignatureOffset(); }
    offset_t peOptHdrOffset() { return core.peOptHdrOffset(); }
    offset_t secHdrsOffset() { return core.secHdrsOffset(); }
    bufsize_t hdrsSize() { return core.hdrsSize(); }
    offset_t getMinSecRVA();

    ResourcesAlbum* getResourcesAlbum() const { return this->album; }

    //get Rich header (if available)
    pe::RICH_SIGNATURE* getRichHeaderSign();
    pe::RICH_DANS_HEADER* getRichHeaderBgn(pe::RICH_SIGNATURE* sign);

    IMAGE_DATA_DIRECTORY* getDataDirectory();
    offset_t peDataDirOffset();

    size_t hdrSectionsNum();
    size_t getSectionsCount(bool useMapped = true);
    exe_bits getHdrBitMode() { return core.getHdrBitMode(); }

    SectionHdrWrapper* getSecHdr(size_t index) const
    {
        return (sects) ? sects->getSecHdr(index) : NULL;
    }

    SectionHdrWrapper* getSecHdrAtOffset(offset_t offset, Executable::addr_type aType, bool roundup, bool verbose = false)
    {
        return (sects == NULL) ? NULL : sects->getSecHdrAtOffset(offset, aType, roundup, verbose);
    }

    size_t getSecIndex(SectionHdrWrapper *sec) const
    {
        return (sects) ?  sects->getSecIndex(sec) : SectHdrsWrapper::SECT_INVALID_INDEX;
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
    bool canAddNewSection();
    SectionHdrWrapper* addNewSection(QString name, bufsize_t size);
    SectionHdrWrapper* extendLastSection(bufsize_t addedSize);
    bool unbindImports();

    /* wrappers for fetching commonly used directories */
    ImportDirWrapper* getImports()
    {
        return dynamic_cast<ImportDirWrapper*>(getWrapper(PEFile::WR_DIR_ENTRY + pe::DIR_IMPORT));
    }
    
    DelayImpDirWrapper* getDelayedImports()
    {
        return dynamic_cast<DelayImpDirWrapper*>(getWrapper(PEFile::WR_DIR_ENTRY + pe::DIR_DELAY_IMPORT));
    }

    ExportDirWrapper* getExports()
    {
        return dynamic_cast<ExportDirWrapper*>(getWrapper(PEFile::WR_DIR_ENTRY + pe::DIR_EXPORT));
    }

    /* All Entry Points of the application, including: main EP, Exports, TLS Callbacks */
    virtual size_t getAllEntryPoints(QMap<offset_t,QString> &entrypoints, Executable::addr_type aType = Executable::RVA) 
    {
        size_t initialSize = entrypoints.size();
        
        Executable::getAllEntryPoints(entrypoints, aType);
        this->getExportsMap(entrypoints, aType);
        
        return entrypoints.size() - initialSize;
    }

    offset_t getLastMapped(Executable::addr_type aType);

    //calculate the real section headers end
    offset_t secHdrsEndOffset()
    {
        const offset_t secHdrSize = this->getSectionsCount(false) * sizeof(IMAGE_SECTION_HEADER);
        return secHdrsOffset() + secHdrSize;
    }

protected:
    size_t getExportsMap(QMap<offset_t,QString> &entrypoints, Executable::addr_type aType = Executable::RVA);
    
    virtual void clearWrappers();
    virtual void wrap(AbstractByteBuffer *v_buf);

    void initDirEntries();
    PECore core;
    //---
    //modifications:
    bool setHdrSectionsNum(size_t newNum);
    bool setVirtualSize(bufsize_t newSize);

    DosHdrWrapper *dosHdrWrapper;

    FileHdrWrapper *fHdr;
    OptHdrWrapper *optHdr;
    SectHdrsWrapper *sects;

    ResourcesAlbum *album;
    DataDirEntryWrapper* dataDirEntries[pe::DIR_ENTRIES_COUNT];

friend class SectHdrsWrapper;
};


