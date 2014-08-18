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
    wrapDataDirs(this);
}

void PEFile::wrapDataDirs(AbstractByteBuffer *v_buf)
{
    importDir = new ImportDirWrapper(this);
    this->wrappers[WR_IMPORTS] = importDir;

    this->wrappers[WR_DELAYIMPORTS] = new DelayImpDirWrapper(this);
    this->wrappers[WR_BOUNDIMPORTS] = new BoundImpDirWrapper(this);
    this->wrappers[WR_DEBUG] = new DebugDirWrapper(this);
    this->wrappers[WR_EXPORTS] = new ExportDirWrapper(this);
    this->wrappers[WR_SECURITY] = new SecurityDirWrapper(this);
    this->wrappers[WR_TLS] = new TlsDirWrapper(this);
    this->wrappers[WR_LDCONF] = new LdConfigDirWrapper(this); //WR_BASERELOC
    this->wrappers[WR_BASERELOC] = new RelocDirWrapper(this);
    this->wrappers[WR_EXCEPTION] = new ExceptionDirWrapper(this);
    this->wrappers[WR_RESOURCES] = new ResourceDirWrapper(this, album);

    if (this->album) {
        this->album->wrapLeafsContent();
    }
}

offset_t PEFile::peHdrOffset()
{
    return core.peFileHdrOffset();
}

offset_t PEFile::peNtHdrOffset()
{
    return core.peSignatureOffset();
}

offset_t PEFile::secHdrsOffset()
{
    return core.secHdrsOffset();
}

offset_t PEFile::peOptHdrOffset()
{
    return core.peOptHdrOffset();
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

Executable::exe_bits PEFile::getHdrBitMode()
{
    return core.getHdrBitMode();
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

bufsize_t PEFile::getAlignment(Executable::addr_type aType)
{
    return core.getAlignment(aType);
}

offset_t PEFile::getImageBase()
{
    return core.getImageBase();
}

offset_t PEFile::getEntryPoint()
{
    if (optHdr == NULL) return 0;

    bool isOk = false;
    offset_t entryPoint = static_cast<offset_t> (optHdr->getNumValue(OptHdrWrapper::EP, &isOk));
    if (isOk == false) return INVALID_ADDR;
    return entryPoint;
}

offset_t PEFile::getWrapperRawOffset(int wrapperId)
{
    if (wrapperId <= WR_NONE || wrapperId >= COUNT_WRAPPERS ) return INVALID_ADDR;

    switch (wrapperId) {
        case WR_DOS_HDR : return 0;
        case WR_FILE_HDR: return this->peHdrOffset();
        case WR_OPTIONAL_HDR: return this->peNtHdrOffset();
        case WR_DATADIR : return this->peDataDirOffset();
        case WR_SECTIONS : return this->secHdrsOffset();
    }
    return INVALID_ADDR;
}

size_t PEFile::hdrSectionsNum()
{
    bool isOk = false;
    uint64_t secNum = this->fHdr->getNumValue(FileHdrWrapper::SEC_NUM , &isOk);
    if (isOk == false) return 0;

    return static_cast<size_t> (secNum);
}


offset_t PEFile::fileAddrToRva(offset_t raw, bool getClosestIfInCave)
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
        return bgnVA+ curr;
    }
    //TODO...
    return raw;
}

offset_t PEFile::VaToFileAddr(offset_t va, bool getClosestIfInCave)
{
    if (va >= this->getMappedSize(Executable::VA)) return INVALID_ADDR;

    SectionHdrWrapper* sec = this->getSecHdrAtOffset(va, Executable::VA, true);
    if (sec) {
        offset_t bgnVA = sec->getContentOffset(Executable::VA);
        offset_t bgnRaw = sec->getContentOffset(Executable::RAW);
        if (bgnVA  == INVALID_ADDR || bgnRaw == INVALID_ADDR) return INVALID_ADDR;

        bufsize_t curr = (va - bgnVA);
        bufsize_t rawSize = sec->getContentSize(Executable::RAW, true);
        if (curr >= rawSize) {
            //address out of section. return last addr of the section.
            return bgnRaw + rawSize;
        }
        return bgnRaw + curr;
    }
    //TODO...
    return va;
}

offset_t PEFile::rvaToFileAddr(offset_t rva, bool getClosestIfInCave)
{
    offset_t va = rva;
    return VaToFileAddr(va, getClosestIfInCave);
}

offset_t PEFile::rvaToVa(offset_t rva) { return rva; }

