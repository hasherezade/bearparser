#include "pe/PECore.h"

#define DEFAULT_IMGBASE 0x10000

void PECore::reset()
{
    dos = NULL;
    fHdr = NULL;
    opt32 = NULL;
    opt64 = NULL;
}

bool PECore::wrap(AbstractByteBuffer *v_buf)
{
    buf = v_buf;
    bool allowExceptions = true;
    // reset all:
    reset();

    offset_t offset = 0;
    this->dos = (IMAGE_DOS_HEADER*) buf->getContentAt(offset, sizeof(IMAGE_DOS_HEADER), allowExceptions);
    if (dos == NULL) throw ExeException("Could not wrap PECore: invalid DOS Header!");

    offset = dos->e_lfanew + sizeof(DWORD); //skip 'PE' signature
    this->fHdr = (IMAGE_FILE_HEADER*) buf->getContentAt(offset, sizeof(IMAGE_FILE_HEADER), allowExceptions);
    if (fHdr == NULL)  throw ExeException("Could not wrap PECore!");

    offset = offset + sizeof(IMAGE_FILE_HEADER);
    WORD *magic = (WORD*) buf->getContentAt(offset, sizeof(WORD), allowExceptions);
    if (magic == NULL)  throw ExeException("Could not wrap PECore: invalid FileHeader");

    Executable::exe_bits mode = Executable::BITS_32;
    if ((*magic) == pe::OH_NT64) {//32 = 0x10B) {
        mode = Executable::BITS_64;
    }

    if (mode == Executable::BITS_32) {
        this->opt32 = (IMAGE_OPTIONAL_HEADER32*) buf->getContentAt(offset, sizeof(IMAGE_OPTIONAL_HEADER32), allowExceptions);

    } else if (mode == Executable::BITS_64) {
        this->opt64 = (IMAGE_OPTIONAL_HEADER64*) buf->getContentAt(offset, sizeof(IMAGE_OPTIONAL_HEADER64), allowExceptions);
    }
    if ( this->opt32 == NULL && this->opt64 == NULL) {
        throw ExeException("Could not wrap PECore : invalid OptionalHeader");
   }
   return true;
}

Executable::exe_bits PECore::getHdrBitMode() const
{
    if (opt32) return Executable::BITS_32;
    if (opt64) return Executable::BITS_64;

    return Executable::BITS_32; // DEFAULT
}

offset_t PECore::peSignatureOffset() const
{
    return static_cast<offset_t> (dos->e_lfanew);
}

offset_t PECore::peFileHdrOffset() const
{
    const offset_t offset = peSignatureOffset();
    if (offset == INVALID_ADDR) {
        return INVALID_ADDR;
    }
    const offset_t signSize = sizeof(DWORD);
    return offset + signSize;
}

offset_t PECore::peOptHdrOffset() const 
{
    const offset_t offset = peFileHdrOffset();
    if (offset == INVALID_ADDR) {
        return INVALID_ADDR;
    }
    return offset + sizeof(IMAGE_FILE_HEADER);
}

bufsize_t PECore::peNtHeadersSize() const
{
    if (this->getHdrBitMode() == Executable::BITS_64)
        return sizeof(IMAGE_NT_HEADERS64);

    return sizeof(IMAGE_NT_HEADERS32);
}

offset_t PECore::secHdrsOffset() const
{
    const offset_t offset = peOptHdrOffset();
    if (offset == INVALID_ADDR) {
        return INVALID_ADDR;
    }
    if (!fHdr) {
        return INVALID_ADDR;
    }
    const offset_t size = static_cast<offset_t>(this->fHdr->SizeOfOptionalHeader);
    return offset + size;
}

bufsize_t PECore::getAlignment(Executable::addr_type aType)
{
    if (this->opt32) {
        if (aType == Executable::RAW) return opt32->FileAlignment;
        return opt32->SectionAlignment;
    }
    if (this->opt64) {
        if (aType == Executable::RAW) return opt64->FileAlignment;
        return opt64->SectionAlignment;
    }
    return 0;
}

bufsize_t PECore::getImageSize()
{
    bufsize_t imgSize = 0;
    if (this->opt32) {
        imgSize = opt32->SizeOfImage;
    }
    if (this->opt64) {
        imgSize = opt64->SizeOfImage;
    }
    return imgSize;
}

bufsize_t PECore::hdrsSize() const
{
    bufsize_t hdrsSize = 0;
    if (this->opt32) {
        hdrsSize = opt32->SizeOfHeaders;
    }
    if (this->opt64) {
        hdrsSize = opt64->SizeOfHeaders;
    }
    return hdrsSize;
}

offset_t PECore::getImageBase()
{
    offset_t imgBase = 0;
    if (this->opt32) {
        imgBase = opt32->ImageBase;
    }
    if (this->opt64) {
        imgBase = opt64->ImageBase;
    }
    //can be null, under XP. In this case, the binary will be relocated to 10000h
    //(quote: http://code.google.com/p/corkami/wiki/PE)
    if (imgBase == 0) {
        imgBase = DEFAULT_IMGBASE;
    }

    //in 32 bit PEs: it can be any value as long as ImageBase + 'SizeOfImage' < 80000000h
    //if the ImageBase is bigger than that, the binary will be relocated to 10000h
    if (this->opt32) {
        offset_t maxOffset = this->getImageSize() + imgBase;
        if (maxOffset >= 0x80000000) {
            imgBase = DEFAULT_IMGBASE;
        }
    }
    return imgBase;
}

