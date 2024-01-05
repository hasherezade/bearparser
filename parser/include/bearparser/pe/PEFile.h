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
#include "CommonOrdinalsLookup.h"
#include "rsrc/ResourcesAlbum.h"

#include "../WatchedLocker.h"

#define PE_SHOW_LOCK false

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

    static long computeChecksum(BYTE *buffer, size_t bufferSize, offset_t checksumOffset);

    PEFile(AbstractByteBuffer *v_buf);
    virtual ~PEFile() { clearWrappers(); delete album; }
    
    virtual void wrap(); // inherited from Executable
    
    virtual bufsize_t getMappedSize(Executable::addr_type aType);
    virtual bufsize_t getAlignment(Executable::addr_type aType) const { return core.getAlignment(aType); }
    virtual offset_t getImageBase(bool recalculate = false) { return core.getImageBase(recalculate); }
    virtual offset_t getEntryPoint(Executable::addr_type addrType = Executable::RVA); // returns INVALID_ADDR if failed

    virtual exe_bits getBitMode() { return getHdrBitMode(); }
    //---
    // PEFile only:
    offset_t peFileHdrOffset() const { return core.peFileHdrOffset(); }
    offset_t peNtHdrOffset() const { return core.peSignatureOffset(); }
    bufsize_t peNtHeadersSize() const { return core.peNtHeadersSize(); }
    offset_t peOptHdrOffset() const { return core.peOptHdrOffset(); }
    offset_t secHdrsOffset() const { return core.secHdrsOffset(); }

    bufsize_t hdrsSize() { return core.hdrsSize(); }

    ResourcesAlbum* getResourcesAlbum() const { return this->album; }

    //get Rich header (if available)
    pe::RICH_SIGNATURE* getRichHeaderSign();
    pe::RICH_DANS_HEADER* getRichHeaderBgn(pe::RICH_SIGNATURE* sign);

    IMAGE_DATA_DIRECTORY* getDataDirectory();
    offset_t peDataDirOffset();

    size_t hdrSectionsNum() const;

    exe_bits getHdrBitMode() { return core.getHdrBitMode(); }

/* mutex protected: section operations */

    offset_t getLastMapped(Executable::addr_type aType)
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        return _getLastMapped(aType);
    }
    
    // FileAddr <-> RVA
    virtual offset_t rawToRva(offset_t raw);
    virtual offset_t rvaToRaw(offset_t rva);
    
    offset_t getMinSecRVA();

    size_t getSectionsCount(bool useMapped = true)
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        return _getSectionsCount(useMapped);
    }

    // mutex protected
    size_t getSecIndex(SectionHdrWrapper *sec)
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        return _getSecIndex(sec);
    }
    
    // mutex protected
    SectionHdrWrapper* getSecHdr(size_t index)
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        return _getSecHdr(index);
    }

    // mutex protected
    SectionHdrWrapper* getSecHdrAtOffset(offset_t offset, Executable::addr_type aType, bool recalculate = false, bool verbose = false)
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        return _getSecHdrAtOffset(offset, aType, recalculate, verbose);
    }
    
    // mutex protected
    SectionHdrWrapper* getEntrySection()
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        offset_t ep = getEntryPoint(Executable::RVA);
        return this->_getSecHdrAtOffset(ep, Executable::RVA, true, false);
    }
    
    // mutex protected
    BYTE* getSecContent(SectionHdrWrapper *sec)
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        if (this->_getSecIndex(sec) == SectHdrsWrapper::SECT_INVALID_INDEX) {
            return NULL; //not my section
        }
        const bufsize_t buf_size = sec->getContentSize(Executable::RAW, true);
        if (!buf_size) return NULL;

        offset_t start = sec->getContentOffset(Executable::RAW, true);
        BYTE *ptr = this->getContentAt(start, buf_size);
        return ptr;
    }
    
    // mutex protected
    BufferView* createSectionView(size_t secNum);
    //---
    
    // mutex protected
    bool clearContent(SectionHdrWrapper *sec)
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        if (this->_getSecIndex(sec) == SectHdrsWrapper::SECT_INVALID_INDEX) {
            return false; //not my section
        }
        BufferView *secView = this->_createSectionView(sec);
        if (!secView) return false;

        bool isOk = secView->fillContent(0);
        delete secView;
        return isOk;
    }
    
    // mutex protected
    offset_t secHdrsEndOffset()
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        return _secHdrsEndOffset();
    }
    
    // mutex protected
    SectionHdrWrapper* getLastSection()
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        return this->_getLastSection();
    }

    // mutex protected
    bool canAddNewSection()
    {
        WatchedLocker lock(&m_peMutex, PE_SHOW_LOCK, __FUNCTION__);
        return this->_canAddNewSection();
    }
    
    // mutex protected
    SectionHdrWrapper* addNewSection(QString name, bufsize_t size, bufsize_t v_size=0);
    
    // mutex protected
    SectionHdrWrapper* extendLastSection(bufsize_t addedSize);
    
    // mutex protected
    bool dumpSection(SectionHdrWrapper *sec, QString fileName);
    
/* resource operations */

    ResourcesContainer*  getResourcesOfType(pe::resource_type typeId)
    {
        return (this->album == NULL) ? NULL : album->getResourcesOfType(typeId);
    }

    DataDirEntryWrapper* getDataDirEntry(pe::dir_entry eType);

    //modifications:
    bool setEntryPoint(offset_t entry, Executable::addr_type aType);
    bool moveDataDirEntry(pe::dir_entry id, offset_t newOffset, Executable::addr_type addType = Executable::RAW); //throws CustomException

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

    /* wrappers:
    */
    bool hasDirectory(pe::dir_entry dirNum)
    {
        return this->getDataDirEntry(dirNum) ? true : false;
    }

    bufsize_t getFileAlignment() const
    {
        return this->getAlignment(Executable::RAW);
    }

    bufsize_t getSectionAlignment() const
    {
        return this->getAlignment(Executable::RVA);
    }


    void setImageSize(size_t newSize)
    {
        this->setVirtualSize(newSize);
    }

    bool canResize(bufsize_t newSize)
    {
        bufsize_t currentSize = (bufsize_t)this->getRawSize();
        if (newSize > currentSize) {
            return true;
        }
        bufsize_t hEnd = bufsize_t(this->peNtHdrOffset()) + this->peNtHeadersSize();
        if (newSize < hEnd) {
            return false; // the resize will harm headers!
        }
        return true;
    }
    
    bool isReproBuild()
    {
        bool isRepro = false;
        DebugDirWrapper* dbgDir = dynamic_cast<DebugDirWrapper*>(dataDirEntries[pe::DIR_DEBUG]);
        if (dbgDir && dbgDir->isRepro()) {
            isRepro = true;
        }
        return isRepro;
    }

protected:
    void wrapCore();
    
    SectionHdrWrapper* _getLastSection();
    bool _canAddNewSection();

    offset_t _secHdrsEndOffset()
    {
        const offset_t offset = secHdrsOffset();
        if (offset == INVALID_ADDR) {
            return INVALID_ADDR;
        }
        const offset_t secHdrSize = this->_getSectionsCount() * sizeof(IMAGE_SECTION_HEADER);
        return offset + secHdrSize;
    }
    
    offset_t _getLastMapped(Executable::addr_type aType);

    size_t _getSectionsCount(bool useMapped = true) const;
    
    size_t _getSecIndex(SectionHdrWrapper *sec) const
    {
        return (sects) ?  sects->getSecIndex(sec) : SectHdrsWrapper::SECT_INVALID_INDEX;
    }
    
    SectionHdrWrapper* _getSecHdr(size_t index) const
    {
        return (sects) ? sects->_getSecHdr(index) : NULL;
    }

    SectionHdrWrapper* _getSecHdrAtOffset(offset_t offset, Executable::addr_type aType, bool recalculate = false, bool verbose = false)
    {
        return (sects) ? sects->getSecHdrAtOffset(offset, aType, recalculate, verbose) : NULL;
    }
    
    BufferView* _createSectionView(SectionHdrWrapper *sec);
    
    size_t getExportsMap(QMap<offset_t,QString> &entrypoints, Executable::addr_type aType = Executable::RVA);

    virtual void clearWrappers();

    void _init(AbstractByteBuffer *v_buf);
    void initDirEntries();

    //---
    //modifications:
    bool setHdrSectionsNum(size_t newNum);
    bool setVirtualSize(bufsize_t newSize);
    
    PECore core;
    DosHdrWrapper *dosHdrWrapper;

    FileHdrWrapper *fHdr;
    OptHdrWrapper *optHdr;
    SectHdrsWrapper *sects;

    ResourcesAlbum *album;
    DataDirEntryWrapper* dataDirEntries[pe::DIR_ENTRIES_COUNT];
    QMutex m_peMutex;

friend class SectHdrsWrapper;
friend class SectionHdrWrapper;
};

