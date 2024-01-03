#include "pe/PEFile.h"
#include "FileBuffer.h"

bool PEFileBuilder::signatureMatches(AbstractByteBuffer *buf)
{
    if (buf == NULL) return false;

    offset_t dosOffset = 0;
    WORD *magic = (WORD*) buf->getContentAt(dosOffset, sizeof(WORD));
    if (magic == NULL) return false;

    if ((*magic) != pe::S_DOS) {
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
        exe = NULL;
    }
    return exe;
}

//-------------------------------------------------------------
long PEFile::computeChecksum(BYTE* buffer, size_t bufferSize, offset_t checksumOffset)
{
    if (!buffer || !bufferSize) return 0;

    WORD* wordsBuff = reinterpret_cast<WORD*>(buffer);
    const size_t wordsCount = bufferSize / sizeof(WORD);
    const size_t remainingBytes = bufferSize % sizeof(WORD);
    
    size_t checksumBgn = 0;
    size_t checksumEnd = 0;
    if (checksumOffset != INVALID_ADDR) {
        checksumBgn = size_t(checksumOffset);
        checksumEnd = checksumBgn + sizeof(DWORD);
    }

    const long long maxVal = ((long long)1) << 32;
    long long checksum = 0;
    
    for (int i = 0; i < wordsCount; i++) {
        WORD chunk = wordsBuff[i];

        size_t bI = i * sizeof(WORD);
        if (checksumBgn != checksumEnd && bI >= checksumBgn && bI < checksumEnd) {
            size_t mask = (checksumEnd - bI) % sizeof(WORD);
            size_t shift = (sizeof(WORD) - mask) * 8;
            chunk = (chunk >> shift) << shift;
        }

        checksum = (checksum & 0xffffffff) + chunk + (checksum >> 32);
        if (checksum > maxVal) {
            checksum = (checksum & 0xffffffff) + (checksum >> 32);
        }
    }
    
    // Handle the remaining bytes
    if (remainingBytes > 0) {
        WORD chunk = 0;
        memcpy(&chunk, buffer + wordsCount * sizeof(WORD), remainingBytes);

        size_t bI = wordsCount * sizeof(WORD);
        if (checksumBgn != checksumEnd && bI >= checksumBgn && bI < checksumEnd) {
            size_t mask = (checksumEnd - bI) % sizeof(WORD);
            size_t shift = (sizeof(WORD) - mask) * 8;
            chunk = (chunk >> shift) << shift;
        }

        checksum = (checksum & 0xffffffff) + chunk + (checksum >> 32);
        if (checksum > maxVal) {
            checksum = (checksum & 0xffffffff) + (checksum >> 32);
        }
    }
    checksum = (checksum & 0xffff) + (checksum >> 16);
    checksum = (checksum)+(checksum >> 16);
    checksum = checksum & 0xffff;
    checksum += bufferSize;
    return checksum;
}

///---

PEFile::PEFile(AbstractByteBuffer *v_buf)
    : MappedExe(v_buf, Executable::BITS_32), dosHdrWrapper(NULL), fHdr(NULL), optHdr(NULL), sects(NULL),
    album(NULL)
{
    clearWrappers();

    init(v_buf);
    Logger::append(Logger::D_INFO,"Wrapped");
}

void PEFile::init(AbstractByteBuffer *v_buf)
{
    // wrap the core:
    core.wrap(v_buf);

    album = new ResourcesAlbum(this);
    
    //generate wrappers:
    this->dosHdrWrapper = new DosHdrWrapper(this);
    this->wrappers[WR_DOS_HDR] = this->dosHdrWrapper;

    this->fHdr = new FileHdrWrapper(this);
    if (fHdr->getPtr() == NULL) throw ExeException("Cannot parse FileHdr: It is not PE File!");
    this->wrappers[WR_FILE_HDR] = fHdr;
    this->wrappers[WR_RICH_HDR] = new RichHdrWrapper(this);

    this->optHdr = new OptHdrWrapper(this);
    if (optHdr->getPtr() == NULL) throw ExeException("Cannot parse OptionalHeader: It is not PE File!");
    this->wrappers[WR_OPTIONAL_HDR] = optHdr;

    this->sects = new SectHdrsWrapper(this);
    this->wrappers[WR_SECTIONS] = sects;

    this->wrappers[WR_DATADIR] = new DataDirWrapper(this);
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
    dataDirEntries[pe::DIR_COM_DESCRIPTOR] = new ClrDirWrapper(this); 
 
    for (int i = 0; i < pe::DIR_ENTRIES_COUNT; i++) {
        this->wrappers[WR_DIR_ENTRY + i] = dataDirEntries[i];
    }
}


void PEFile::clearWrappers()
{
    initDirEntries();
    MappedExe::clearWrappers();

    this->dosHdrWrapper = NULL;
    this->fHdr = NULL;
    this->optHdr = NULL;
    this->sects = NULL;
}

void PEFile::initDirEntries()
{
    for (size_t i = 0 ; i < pe::DIR_ENTRIES_COUNT; i++) {
        dataDirEntries[i] = NULL;
    }
}

void PEFile::wrap()
{
    PEFile::wrap(this->buf);
}

void PEFile::wrap(AbstractByteBuffer *v_buf)
{
    // rewrap the core:
    core.wrap(v_buf);
/*
    //regenerate the wrappers:
    this->dosHdrWrapper->wrap();

    this->fHdr->wrap();
    if (fHdr->getPtr() == NULL) throw ExeException("Cannot parse FileHdr: It is not PE File!");
    this->wrappers[WR_RICH_HDR]->wrap();

    this->optHdr->wrap();
    if (optHdr->getPtr() == NULL) throw ExeException("Cannot parse OptionalHeader: It is not PE File!");

    this->wrappers[WR_DATADIR]->wrap();

    bool isOk = false;
    const size_t secNum = fHdr->getNumValue(FileHdrWrapper::SEC_NUM, &isOk);
    if (isOk && secNum){
        this->sects = new SectHdrsWrapper(this);
        this->wrappers[WR_SECTIONS] = sects;
    }
    else {
        this->sects = NULL;
    }

    for (size_t i = 0 ; i < pe::DIR_ENTRIES_COUNT; i++) {
        dataDirEntries[i]->wrap();
    }
*/
    this->sects->wrap();
    
    if (this->album) {
        this->album->wrapLeafsContent();
    }
}

pe::RICH_DANS_HEADER* PEFile::getRichHeaderBgn(pe::RICH_SIGNATURE* richSign)
{
    if (!richSign) return NULL;

    DWORD xorkey = richSign->checksum;
    const offset_t richOffset = this->getOffset(richSign);

    pe::RICH_DANS_HEADER* dansHdr = NULL;

    offset_t offset = richOffset - sizeof(pe::RICH_DANS_HEADER);
    while (offset > 0) {
        dansHdr = (pe::RICH_DANS_HEADER*) this->getContentAt(offset, sizeof(pe::RICH_DANS_HEADER));
        if (!dansHdr) {
            break;
        }
        if (dansHdr->dansId == (pe::DANS_HDR_MAGIC ^ xorkey)) {
            break; //got it!
        }
        //walking back
        offset -= sizeof(DWORD);
    }
    if (!dansHdr || dansHdr->dansId != (pe::DANS_HDR_MAGIC ^ xorkey)) {
        return NULL; //not found
    }
    return dansHdr;
}

pe::RICH_SIGNATURE* PEFile::getRichHeaderSign()
{
    size_t dosStubOffset = this->core.dos->e_lfarlc;
    size_t dosStubEnd = this->core.dos->e_lfanew; // PE header start
    const size_t maxSize = dosStubEnd - dosStubOffset; // Rich Header is somewhere in the space between DOS and PE headers
    BYTE *dosPtr = this->getContentAt(dosStubOffset, maxSize);
    if (!dosPtr) {
        return NULL;
    }

    pe::RICH_SIGNATURE* richSign = NULL;
    size_t toSearchSize = maxSize;
    const offset_t startOffset = dosStubOffset; //we are starting from the beginning of DOS stub
    const size_t step = sizeof(DWORD); //RichHeader is padded by DWORDS

    while (toSearchSize > 0) {
        richSign = (pe::RICH_SIGNATURE*) this->getContentAt(startOffset + toSearchSize, sizeof(pe::RICH_SIGNATURE));
        if (!richSign) break;
        if (richSign->richId == pe::RICH_HDR_MAGIC) break; //got it!
        // the search goes backward. 
        toSearchSize -= step;
    }
    if (!richSign) return NULL;
    if (richSign->richId != pe::RICH_HDR_MAGIC) {
        return NULL; //invalid
    }
    return richSign;
}


offset_t PEFile::getMinSecRVA()
{
    if (!this->getSectionsCount()) {
        return INVALID_ADDR;
    }
    SectionHdrWrapper* sec = this->_getSecHdr(0);
    if (!sec) {
        return INVALID_ADDR;
    }
    return sec->getContentOffset(Executable::RVA);
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
    if (aType == Executable::NOT_ADDR) return 0;

    if (aType == Executable::RAW) {
        return this->getContentSize();
    }
    const size_t unit_size = 0x1000;
    bufsize_t vSize = 0;
    if (aType == Executable::VA || aType == Executable::RVA) {
        vSize = core.getImageSize();
    }
    if (vSize < unit_size) {
        return unit_size;
    }
    return vSize;
}

offset_t PEFile::getEntryPoint(Executable::addr_type addrType)
{
    if (optHdr == NULL) return INVALID_ADDR;

    bool isOk = false;
    offset_t entryPoint = static_cast<offset_t> (optHdr->getNumValue(OptHdrWrapper::EP, &isOk));
    if (isOk == false) return INVALID_ADDR;

    const Executable::addr_type epType = Executable::RVA;
    if (addrType != epType) {
        entryPoint = this->convertAddr(entryPoint, epType, addrType);
    }
    return entryPoint;
}

bool PEFile::setEntryPoint(offset_t entry, Executable::addr_type aType)
{
    if (optHdr == NULL) return false;

    offset_t epRva = this->convertAddr(entry, aType, Executable::RVA);
    bool isOk = optHdr->setNumValue(OptHdrWrapper::EP, epRva);
    return isOk;
}

size_t PEFile::hdrSectionsNum() const
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
        Logger::append(Logger::D_ERROR,"Can not change FileHdr!");
        return false;
    }
    return true;
}

bool PEFile::setVirtualSize(bufsize_t newSize)
{
    uint64_t size = newSize;
    bool canSet = optHdr->setNumValue(OptHdrWrapper::IMAGE_SIZE, size);
    if (canSet == false) {
        Logger::append(Logger::D_ERROR, "Can not change OptHdr!");
        return false;
    }
    return true;
}

size_t PEFile::getSectionsCount(bool useMapped) const
{
    if (useMapped == false) {
        return hdrSectionsNum();
    }
    return (this->sects) ? this->sects->getEntriesCount() : 0;
}

offset_t PEFile::rawToRva(offset_t raw)
{
    if (raw >= this->getMappedSize(Executable::RAW)) return INVALID_ADDR;

    SectionHdrWrapper* sec = this->_getSecHdrAtOffset(raw, Executable::RAW, true);
    if (sec) {
        offset_t bgnVA = sec->getContentOffset(Executable::VA);
        offset_t bgnRaw = sec->getContentOffset(Executable::RAW);
        if (bgnVA  == INVALID_ADDR || bgnRaw == INVALID_ADDR) return INVALID_ADDR;

        bufsize_t curr = (raw - bgnRaw);
       
        bufsize_t vSize = sec->getContentSize(Executable::VA, true);
        if (curr >= vSize) {
            //address out of section
            return INVALID_ADDR;
        }
        return bgnVA + curr;
    }
    //TODO: make more tests
    if (this->getSectionsCount() == 0) return raw;
    if (raw < this->hdrsSize()) {
        return raw;
    } //else: content that is between the end of sections headers and the first virtual section is not mapped
    return INVALID_ADDR;
}

offset_t PEFile::rvaToRaw(offset_t rva)
{
    if (rva >= this->getMappedSize(Executable::RVA)) return INVALID_ADDR;

    SectionHdrWrapper* sec = this->_getSecHdrAtOffset(rva, Executable::RVA, true);
    if (sec) {
        offset_t bgnRVA = sec->getContentOffset(Executable::RVA);
        offset_t bgnRaw = sec->getContentOffset(Executable::RAW);
        if (bgnRVA  == INVALID_ADDR || bgnRaw == INVALID_ADDR) return INVALID_ADDR;

        bufsize_t curr = (rva - bgnRVA);
        bufsize_t rawSize = sec->getContentSize(Executable::RAW, true);
        if (curr >= rawSize) {
            // the address might be in a virtual cave that is not related to any raw address
            return INVALID_ADDR;
        }
        return bgnRaw + curr;
    }
    if (rva >= this->getMappedSize(Executable::RAW)) {
        return INVALID_ADDR;
    }
    if (this->getSectionsCount()) { // do this check only if sections count is non-zero
        if (rva >= this->hdrsSize()) {
            // the address is in the cave between the headers and the first section: cannot be mapped
            return INVALID_ADDR;
        }
    }
    // at this point we are sure that the address is within the raw size:
    return rva;
}

DataDirEntryWrapper* PEFile::getDataDirEntry(pe::dir_entry eType)
{
    if (eType >= pe::DIR_ENTRIES_COUNT) return NULL;
    return dataDirEntries[eType];
}

BufferView* PEFile::createSectionView(size_t secId)
{
    SectionHdrWrapper *sec = this->_getSecHdr(secId);
    if (sec == NULL) {
        Logger::append(Logger::D_WARNING, "No such section");
        return NULL;
    }
    return _createSectionView(sec);
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
    offset_t dataDirAddr = this->convertAddr(newOffset, addrType, dataDirAddrType);
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
    const size_t secCount = hdrSectionsNum();
    if (secCount == SectHdrsWrapper::SECT_COUNT_MAX) return false; //limit exceeded

    //TODO: some more checks? overlay?
    return true;
}


SectionHdrWrapper* PEFile::addNewSection(QString name, bufsize_t size, bufsize_t v_size)
{
    if (canAddNewSection() == false) return NULL;

    ExeNodeWrapper* sec = dynamic_cast<ExeNodeWrapper*>(getWrapper(PEFile::WR_SECTIONS));
    if (!v_size) v_size = size;

    bufsize_t roundedRawEnd = buf_util::roundupToUnit(getMappedSize(Executable::RAW), getAlignment(Executable::RAW));
    bufsize_t roundedVirtualEnd = buf_util::roundupToUnit(getMappedSize(Executable::RVA), getAlignment(Executable::RVA));
    bufsize_t newSize = roundedRawEnd + size;
    bufsize_t newVirtualSize = roundedVirtualEnd + v_size;

    if (setVirtualSize(newVirtualSize) == false) {
        Logger::append(Logger::D_ERROR, "Failed to change virtual size");
        return NULL;
    }

    if (resize(newSize) == false) {
        Logger::append(Logger::D_ERROR, "Failed to resize");
        return NULL;
    }
    // fetch again after resize:
    sec = dynamic_cast<ExeNodeWrapper*>(getWrapper(PEFile::WR_SECTIONS));
    if (sec == NULL) {
        return NULL;
    }

    IMAGE_SECTION_HEADER secHdr;
    ::memset(&secHdr, 0, sizeof(IMAGE_SECTION_HEADER));

    //name copy:
    const size_t nameLen = name.length();
    const size_t bufSize = sizeof(secHdr.Name);
    const size_t copySize = (nameLen < bufSize) ? nameLen : bufSize;
    if (copySize) {
        ::memcpy(secHdr.Name, name.toStdString().c_str(), copySize);
    }

    secHdr.PointerToRawData = static_cast<DWORD>(roundedRawEnd);
    secHdr.VirtualAddress = static_cast<DWORD>(roundedVirtualEnd);
    secHdr.SizeOfRawData = size;
    secHdr.Misc.VirtualSize = v_size;

    SectionHdrWrapper wr(this, &secHdr);
    SectionHdrWrapper* secHdrWr = dynamic_cast<SectionHdrWrapper*>(sec->addEntry(&wr));
    return secHdrWr;
}

SectionHdrWrapper* PEFile::getLastSection()
{
    size_t secCount = this->getSectionsCount(true);
    if (secCount == 0) return NULL;
    return this->_getSecHdr(secCount - 1);
}

offset_t PEFile::getLastMapped(Executable::addr_type aType)
{
    offset_t lastMapped = 0;

    /* check sections bounds */
    const size_t secCounter = this->getSectionsCount(true);
    if (!secCounter) {
        // if PE file has no sections, full file will be mapped
        return getMappedSize(aType);
    }
    for (size_t i = 0; i < secCounter; i++) {
        SectionHdrWrapper *sec = this->_getSecHdr(i);
        if (!sec) continue;

        offset_t secLastMapped= sec->getContentOffset(aType, true);
        if (secLastMapped == INVALID_ADDR) continue;

        const size_t size = (aType == Executable::RAW) ? sec->getMappedRawSize() : sec->getMappedVirtualSize();
        if (size == 0) continue; // exclude not mapped sections
        
        secLastMapped += size;
        if (secLastMapped > lastMapped) {
            lastMapped = secLastMapped;
        }
    }

    /* check header bounds */
    /* section headers: */
    if (lastMapped < this->secHdrsEndOffset()) {
        lastMapped = this->secHdrsEndOffset();
    }
    // PE hdrs ending:
    const offset_t peHdrsEnd = this->core.peSignatureOffset() + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + this->core.peNtHeadersSize();
    if (lastMapped < peHdrsEnd) {
        lastMapped = peHdrsEnd;
    }
    // OptionalHdr -> SizeOfHeaders:
    const offset_t ntHeadersEndOffset = this->core.hdrsSize();
    if (lastMapped < ntHeadersEndOffset) {
        lastMapped = ntHeadersEndOffset;
    }
    return lastMapped;
}

SectionHdrWrapper* PEFile::extendLastSection(bufsize_t addedSize)
{
    SectionHdrWrapper* secHdr = getLastSection();
    if (secHdr == NULL) return NULL;

    //TODO: check overlay...
    bufsize_t fullSize = getContentSize();
    bufsize_t newSize = fullSize + addedSize;

    offset_t secROffset = secHdr->getContentOffset(Executable::RAW, false);
    if (secROffset == INVALID_ADDR) {
        return NULL;
    }
    const bufsize_t secNewRSize = newSize - secROffset; //include overlay in section

    secHdr->setNumValue(SectionHdrWrapper::RSIZE, uint64_t(secNewRSize));

    const offset_t secVOffset = secHdr->getContentOffset(Executable::RVA, false);
    const bufsize_t secVSize = secHdr->getContentSize(Executable::RVA, false);

    // if the previous virtual size is smaller than the new raw size, then update it:
    if (secVSize < secNewRSize) {
        secHdr->setNumValue(SectionHdrWrapper::VSIZE, uint64_t(secNewRSize));

        // if the virtual size of section has changed,
        // update the Size of Image (saved in the header):
        bufsize_t newVSize = secVOffset + secNewRSize;
        this->setVirtualSize(newVSize);
    }

    //update raw size:
    this->resize(newSize);
    //finally, retrieve the resized section:
    return getLastSection();
}

bool PEFile::unbindImports()
{
    IMAGE_DATA_DIRECTORY* ddir = this->getDataDirectory();
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

bool PEFile::dumpSection(SectionHdrWrapper *sec, QString fileName)
{
    if (this->_getSecIndex(sec) == SectHdrsWrapper::SECT_INVALID_INDEX) {
        return false; //not my section
    }
    BufferView *secView = this->_createSectionView(sec);
    if (!secView) return false;

    bufsize_t dumpedSize = FileBuffer::dump(fileName, *secView, false);
    delete secView;

    return dumpedSize ? true : false;
}

//protected:

BufferView* PEFile::_createSectionView(SectionHdrWrapper *sec)
{
    Executable::addr_type aType = Executable::RAW;
    offset_t start = sec->getContentOffset(aType, true);
    bufsize_t size = sec->getContentSize(aType, true);
    if (start == INVALID_ADDR || size == 0) {
        return NULL;
    }
    return new BufferView(this, start, size);
}

size_t PEFile::getExportsMap(QMap<offset_t,QString> &entrypoints, Executable::addr_type aType)
{
    size_t initialSize = entrypoints.size();

    ExportDirWrapper* exports = dynamic_cast<ExportDirWrapper*>(this->getWrapper(PEFile::WR_DIR_ENTRY + pe::DIR_EXPORT));
    if (!exports) return 0;
        
    const size_t entriesCnt = exports->getEntriesCount();
    if (entriesCnt == 0) return 0;

    for (int i = 0; i < entriesCnt; i++) {
        ExportEntryWrapper* entry = dynamic_cast<ExportEntryWrapper*>(exports->getEntryAt(i));
        if (!entry) continue;

        QString forwarder = entry->getForwarderStr();
        if (forwarder.length()) {
            continue;
        }
        offset_t rva = entry->getFuncRva();
        offset_t offset = this->convertAddr(rva, Executable::RVA, aType);
        if (offset == INVALID_ADDR) {
            continue;
        }
        entrypoints.insert(offset, entry->getName());
    }
    return entrypoints.size() - initialSize;
}
