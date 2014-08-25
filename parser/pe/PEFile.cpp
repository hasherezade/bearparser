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
    : DOSExe(v_buf), fHdr(NULL), optHdr(NULL), sects(NULL),
    album(NULL)
{
    bitMode = Executable::BITS_32;
    album = new ResourcesAlbum(this);
    wrap(v_buf);
}

void PEFile::clearWrappers()
{
    MappedExe::clearWrappers();
    TRACE();
    // unmap DirEntries
    for (size_t i = 0 ; i < pe::DIR_ENTRIES_COUNT; i++) {
        dataDirEntries[pe::DIR_ENTRIES_COUNT] = NULL;
    }
}

void PEFile::wrap()
{
    clearWrappers();
    DOSExe::wrap(this->buf);
    PEFile::wrap(this->buf);
}

void  PEFile::wrap(AbstractByteBuffer *v_buf)
{
    core.wrap(v_buf);

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
        sects = new SectHdrsWrapper(this);
        this->wrappers[WR_SECTIONS] = sects;
    }
    // map Data Dirs
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
    if (dataDirEntries[eType] == NULL) return NULL;
    if (dataDirEntries[eType]->getPtr() == NULL) return NULL;
    return dataDirEntries[eType];
}


bool PEFile::moveDataDirEntry(pe::dir_entry id, offset_t newOffset, Executable::addr_type addrType)
{
    DataDirEntryWrapper *entry = getDataDirEntry(id);
    if (entry == NULL) {
        return false;
    }
    DataDirWrapper* ddirWrapper = dynamic_cast<DataDirWrapper*> (this->wrappers[WR_DATADIR]);
    IMAGE_DATA_DIRECTORY *ddir = this->getDataDirectory();
    if (ddirWrapper == NULL || ddir == NULL) {
        return false;
    }
    Executable::addr_type dataDirAddrType = ddirWrapper->containsAddrType(id, DataDirWrapper::ADDRESS);
    offset_t dataDirAddr = this-> convertAddr(newOffset, addrType, dataDirAddrType);
    if (dataDirAddr == INVALID_ADDR) {
        return false;
    }
    offset_t targetRaw = this->toRaw(newOffset, addrType);
    if (entry->copyToOffset(targetRaw) == false) {
        if (DBG_LVL) printf("Cannot copy!\n");
        return false;
    }
    entry->fillContent(0);
    ddir[id].VirtualAddress = static_cast<DWORD> (dataDirAddr);
    return true;
}

