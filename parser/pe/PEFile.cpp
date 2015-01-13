#include "PEFile.h"

bool PEFileBuilder::signatureMatches(AbstractByteBuffer *buf)
{
    if (buf == NULL) return false;

    offset_t dosOffset = 0;
    WORD *magic = (WORD*) buf->getContentAt(dosOffset, sizeof(WORD));
    if (magic == NULL) return false;

    if ((*magic) != S_DOS) {
        return false;
    }
    offset_t newOffset = dosOffset + (sizeof(IMAGE_DOS_HEADER) - sizeof(LONG));
    LONG* lfnew = (LONG*) buf->getContentAt(newOffset, sizeof(LONG));
    if (lfnew == NULL) {
        return false;
    }
    offset_t peOffset = static_cast<offset_t>(*lfnew);
    DWORD *peMagic = (DWORD*) buf->getContentAt(peOffset, sizeof(DWORD));
    if (peMagic == NULL) {
        return false;
    }
    if (*peMagic == pe::S_NT) {
        return true;
    }
    return false;
}

Executable* PEFileBuilder::build(AbstractByteBuffer *buf)
{
    Executable *exe = NULL;
    if (signatureMatches(buf) == false) return NULL;

    try {
        exe = new PEFile(buf);
    } catch (ExeException &e) {
        //
    }
    return exe;
}

//-------------------------------------------------------------

PEFile::PEFile(AbstractByteBuffer *v_buf)
    : MappedExe(v_buf, Executable::BITS_32), dosHdrWrapper(NULL), fHdr(NULL), optHdr(NULL), sects(NULL),
    album(NULL)
{
    album = new ResourcesAlbum(this);
    wrap(v_buf);
}

void PEFile::clearWrappers()
{
    initDirEntries();
    MappedExe::clearWrappers();
    TRACE();
}

void PEFile::initDirEntries()
{
    for (size_t i = 0 ; i < pe::DIR_ENTRIES_COUNT; i++) {
        dataDirEntries[i] = NULL;
    }
}

void PEFile::wrap()
{
    clearWrappers();
    PEFile::wrap(this->buf);
}

void  PEFile::wrap(AbstractByteBuffer *v_buf)
{
    core.wrap(v_buf);
    this->dosHdrWrapper = new DosHdrWrapper(this);
    this->wrappers[WR_DOS_HDR] = this->dosHdrWrapper;

    this->fHdr = new FileHdrWrapper(this);
    if (fHdr->getPtr() == NULL) throw ExeException("Cannot parse FileHdr: It is not PE File!");
    this->wrappers[WR_FILE_HDR] = fHdr;

    this->optHdr = new OptHdrWrapper(this);
    if (optHdr->getPtr() == NULL) throw ExeException("Cannot parse OptionalHeader: It is not PE File!");
    this->wrappers[WR_OPTIONAL_HDR] = optHdr;

    this->wrappers[WR_DATADIR] =  new DataDirWrapper(this);

    bool isOk = false;
    size_t secNum = fHdr->getNumValue(FileHdrWrapper::SEC_NUM, &isOk);
    if (isOk){
        this->sects = new SectHdrsWrapper(this);
        this->wrappers[WR_SECTIONS] = sects;
    }
    // map Data Dirs
    initDirEntries();
    dataDirEntries[pe::DIR_IMPORT] = new ImportDirWrapper(this);
    dataDirEntries[pe::DIR_DELAY_IMPORT] = new DelayImpDirWrapper(this);
    dataDirEntries[pe::DIR_BOUND_IMPORT] = new BoundImpDirWrapper(this);
    dataDirEntries[pe::DIR_DEBUG] = new DebugDirWrapper(this);
    dataDirEntries[pe::DIR_EXPORT] = new ExportDirWrapper(this);
    dataDirEntries[pe::DIR_SECURITY] = new SecurityDirWrapper(this);
    dataDirEntries[pe::DIR_TLS] = new TlsDirWrapper(this);
    dataDirEntries[pe::DIR_LOAD_CONFIG] = new LdConfigDirWrapper(this);
    dataDirEntries[pe::DIR_BASERELOC] = new RelocDirWrapper(this);
    dataDirEntries[pe::DIR_EXCEPTION] = new ExceptionDirWrapper(this);
    dataDirEntries[pe::DIR_RESOURCE] = new ResourceDirWrapper(this, album);

    for (size_t i = 0; i < pe::DIR_ENTRIES_COUNT; i++) {
        this->wrappers[WR_DIR_ENTRY + i] = dataDirEntries[i];
    }

    if (this->album) {
        this->album->wrapLeafsContent();
    }
}

offset_t PEFile::peDataDirOffset()
{
    if (this->optHdr == NULL) return INVALID_ADDR;
    return optHdr->getFieldOffset(OptHdrWrapper::DATA_DIR);
}

IMAGE_DATA_DIRECTORY* PEFile::getDataDirectory()
{
    if (this->wrappers[WR_DATADIR] == NULL) return NULL;
    return static_cast<IMAGE_DATA_DIRECTORY*>(this->wrappers[WR_DATADIR]->getPtr());
}

bufsize_t PEFile::getMappedSize(Executable::addr_type aType)
{
    if (aType == Executable::RAW) {
        return this->getContentSize();
    }
    //TODO...
    if (aType == Executable::VA || aType == Executable::RVA) {
        return core.getImageSize();
    }
    return 0;
}

offset_t PEFile::getEntryPoint()
{
    if (optHdr == NULL) return INVALID_ADDR;

    bool isOk = false;
    offset_t entryPoint = static_cast<offset_t> (optHdr->getNumValue(OptHdrWrapper::EP, &isOk));
    if (isOk == false) return INVALID_ADDR;
    return entryPoint;
}

bool PEFile::setEntryPoint(offset_t entry, Executable::addr_type aType)
{
    if (optHdr == NULL) return false;

    offset_t epRva = this->convertAddr(entry, aType, Executable::RVA);
    bool isOk = optHdr->setNumValue(OptHdrWrapper::EP, epRva);
    return isOk;
}

size_t PEFile::hdrSectionsNum()
{
    bool isOk = false;
    uint64_t secNum = this->fHdr->getNumValue(FileHdrWrapper::SEC_NUM , &isOk);
    if (isOk == false) return 0;

    return static_cast<size_t> (secNum);
}

bool PEFile::setHdrSectionsNum(size_t newNum)
{
    uint64_t count = newNum;
    bool canSet = fHdr->setNumValue(FileHdrWrapper::SEC_NUM , count);
    if (canSet == false) {
        if (DBG_LVL) printf("Can not change FileHdr!\n");
        return false;
    }
    return true;
}

bool PEFile::setVitualSize(bufsize_t newSize)
{
    uint64_t size = newSize;
    bool canSet = optHdr->setNumValue(OptHdrWrapper::IMAGE_SIZE, 0, size);
    if (canSet == false) {
        if (DBG_LVL) printf("Can not change OptHdr!\n");
        return false;
    }
    return true;
}

size_t PEFile::getSectionsCount(bool useMapped)
{
    if (useMapped == false) {
        return hdrSectionsNum();
    }
    return this->sects->getEntriesCount();
}

offset_t PEFile::rawToRva(offset_t raw)
{
    if (raw >= this->getMappedSize(Executable::RAW)) return INVALID_ADDR;

    SectionHdrWrapper* sec = this->getSecHdrAtOffset(raw, Executable::RAW, true);
    if (sec) {
        offset_t bgnVA = sec->getContentOffset(Executable::VA);
        offset_t bgnRaw = sec->getContentOffset(Executable::RAW);
        if (bgnVA  == INVALID_ADDR || bgnRaw == INVALID_ADDR) return INVALID_ADDR;

        bufsize_t curr = (raw - bgnRaw);

        bufsize_t vSize = sec->getContentSize(Executable::VA, true);
        if (curr >= vSize) {
            //address out of section. return last addr of the section.
            return bgnVA + vSize;
        }
        return bgnVA + curr;
    }
    //TODO...
    return raw;
}

offset_t PEFile::rvaToRaw(offset_t rva)
{
    if (rva >= this->getMappedSize(Executable::RVA)) return INVALID_ADDR;

    SectionHdrWrapper* sec = this->getSecHdrAtOffset(rva, Executable::RVA, true);
    if (sec) {
        offset_t bgnRVA = sec->getContentOffset(Executable::RVA);
        offset_t bgnRaw = sec->getContentOffset(Executable::RAW);
        if (bgnRVA  == INVALID_ADDR || bgnRaw == INVALID_ADDR) return INVALID_ADDR;

        bufsize_t curr = (rva - bgnRVA);
        bufsize_t rawSize = sec->getContentSize(Executable::RAW, true);
        if (curr >= rawSize) {
            //address out of section. return last addr of the section.
            return bgnRaw + rawSize;
        }
        return bgnRaw + curr;
    }
    //TODO...
    return rva;
}

DataDirEntryWrapper* PEFile::getDataDirEntry(pe::dir_entry eType)
{
    if (eType >= pe::DIR_ENTRIES_COUNT) return NULL;
    return dataDirEntries[eType];
}

BufferView* PEFile::createSectionView(size_t secId)
{
    SectionHdrWrapper *sec = this->getSecHdr(secId);
    if (sec == NULL) {
        printf("No such section\n");
        return NULL;
    }
    Executable::addr_type aType = Executable::RAW;
    offset_t start = sec->getContentOffset(aType, true);
    bufsize_t size = sec->getContentSize(aType, true);
    if (start == INVALID_ADDR || size == 0) return NULL;

    BufferView *secView = new BufferView(this, start, size);
    return secView;
}

bool PEFile::moveDataDirEntry(pe::dir_entry id, offset_t newOffset, Executable::addr_type addrType)
{
    bool allowExceptions = true; //TODO: configure exception mode outside...

    DataDirEntryWrapper *entry = getDataDirEntry(id);
    if (entry == NULL) {
        if (allowExceptions) throw ExeException("No such Data Directory");
        return false;
    }
    DataDirWrapper* ddirWrapper = dynamic_cast<DataDirWrapper*> (this->wrappers[WR_DATADIR]);
    IMAGE_DATA_DIRECTORY *ddir = this->getDataDirectory();
    if (ddirWrapper == NULL || ddir == NULL) {
        if (allowExceptions) throw ExeException("Cannot fetch DataDirTable");
        return false;
    }
    Executable::addr_type dataDirAddrType = ddirWrapper->containsAddrType(id, DataDirWrapper::ADDRESS);
    offset_t dataDirAddr = this-> convertAddr(newOffset, addrType, dataDirAddrType);
    if (dataDirAddr == INVALID_ADDR) {
        if (allowExceptions) throw ExeException("Invalid new offset");
        return false;
    }
    offset_t targetRaw = this->toRaw(newOffset, addrType);
    if (entry->canCopyToOffset(targetRaw) == false) {
        if (allowExceptions) throw ExeException("Cannot copy: no space at such offset");
        return false;
    }
    if (entry->copyToOffset(targetRaw) == false) {
        if (allowExceptions) throw ExeException("Cannot copy: error occured");
        return false;
    }
    entry->fillContent(0);
    ddir[id].VirtualAddress = static_cast<DWORD> (dataDirAddr);
    return true;
}

bool PEFile::canAddNewSection()
{
    ExeNodeWrapper* sec = dynamic_cast<ExeNodeWrapper*>(getWrapper(PEFile::WR_SECTIONS));
    if (sec == NULL || sec->canAddEntry() == false) {
        return false;
    }
    size_t secCount = hdrSectionsNum();
    if (secCount == SectHdrsWrapper::SECT_COUNT_MAX) return false; //limit exceeded

    //TODO: some more checks? overlay?
    return true;
}


SectionHdrWrapper* PEFile::addNewSection(QString name, bufsize_t size)
{
    if (canAddNewSection() == false) return NULL;

    ExeNodeWrapper* sec = dynamic_cast<ExeNodeWrapper*>(getWrapper(PEFile::WR_SECTIONS));

    bufsize_t roundedRawEnd = buf_util::roundupToUnit(getMappedSize(Executable::RAW), getAlignment(Executable::RAW));
    bufsize_t roundedVirtualEnd = buf_util::roundupToUnit(getMappedSize(Executable::RVA), getAlignment(Executable::RVA));
    bufsize_t newSize = roundedRawEnd + size;
    bufsize_t newVirtualSize = roundedVirtualEnd + size;

    if (setVitualSize(newVirtualSize) == false) {
        printf("Failed to change virtual size");
        return NULL;
    }

    if (resize(newSize) == false) {
        printf("Failed to resize");
        return NULL;
    }
    // fetch again after resize:
    sec = dynamic_cast<ExeNodeWrapper*>(getWrapper(PEFile::WR_SECTIONS));
    if (sec == NULL) {
        return NULL;
    }

    pe::IMAGE_SECTION_HEADER secHdr;
    memset(&secHdr, 0, sizeof(pe::IMAGE_SECTION_HEADER));

    //name copy:
    std::string nameStr = name.toStdString();
    const char *nameChar = nameStr.c_str();
    size_t copySize = sizeof(secHdr.Name);
    size_t nameLen = strlen(nameChar);
    if (nameLen < copySize) copySize = nameLen;
    memcpy(secHdr.Name, nameChar, copySize);

    secHdr.PointerToRawData = static_cast<DWORD>(roundedRawEnd);
    secHdr.VirtualAddress = static_cast<DWORD>(roundedVirtualEnd);
    secHdr.SizeOfRawData = size;
    secHdr.Misc.VirtualSize = size;

    SectionHdrWrapper wr(this, &secHdr);
    SectionHdrWrapper* secHdrWr = dynamic_cast<SectionHdrWrapper*>(sec->addEntry(&wr));
    return secHdrWr;
}

SectionHdrWrapper* PEFile::getLastSection()
{
    size_t secCount = this->getSectionsCount(true);
    if (secCount == 0) return NULL;
    SectionHdrWrapper* secHdr = this->getSecHdr(secCount - 1);
    return secHdr;
}

SectionHdrWrapper* PEFile::extendLastSection(bufsize_t addedSize)
{
    SectionHdrWrapper* secHdr = getLastSection();
    if (secHdr == NULL) return NULL;
    
    //TODO: check overlay...
    bufsize_t fullSize = getContentSize();
    bufsize_t newSize = fullSize + addedSize;

    offset_t secROffset = secHdr->getContentOffset(Executable::RAW, true);
    bufsize_t secRSize = secHdr->getContentSize(Executable::RAW, true);
    bufsize_t secNewRSize = newSize - secROffset; //include overlay in section

    secHdr->setNumValue(SectionHdrWrapper::RSIZE, uint64_t(secNewRSize));

    offset_t secVOffset = secHdr->getContentOffset(Executable::RVA, true);
    bufsize_t secVSize = secHdr->getContentSize(Executable::RVA, true);
    bufsize_t secNewVSize = secVSize;
    if (secNewVSize < secNewRSize) {
        secNewVSize = secNewRSize;
        secHdr->setNumValue(SectionHdrWrapper::VSIZE, uint64_t(secNewVSize));
    }

    bufsize_t prevVSize = this->getMappedSize(Executable::RVA);

    this->resize(newSize);

    bufsize_t newVSize = secVOffset + secNewVSize;
    this->setVitualSize(newVSize);

    secHdr = getLastSection();
    return secHdr;
}

bool PEFile::unbindImports()
{
    pe::IMAGE_DATA_DIRECTORY* ddir = this->getDataDirectory();
    if (ddir[pe::DIR_BOUND_IMPORT].VirtualAddress == 0  && ddir[pe::DIR_BOUND_IMPORT].Size == 0) {
        // No bound imports already, nothing to do here!
        return true;
    }
    ddir[pe::DIR_BOUND_IMPORT].VirtualAddress = 0;
    ddir[pe::DIR_BOUND_IMPORT].Size = 0;
    DataDirEntryWrapper *bImp = this->getDataDirEntry(pe::DIR_BOUND_IMPORT);
    if (bImp == NULL) {
        //printf("No Bound imports wrapper!\n");
        return false; // todo: throw error?
    }
    bool isOk = bImp->wrap();
    //TODO: change timestamp for all library entries from (-1 : BOUND) to 0 : NOT BOUND
    return isOk;
}