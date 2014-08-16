#include "PECore.h"
#define DEFAULT_IMGBASE 0x10000

using namespace pe;

void PECore::reset()
{
    dos = NULL;
    fHdr = NULL;
    opt32 = NULL;
    opt64 = NULL;

    signatureOff = INVALID_ADDR;
    fileHdrOff = INVALID_ADDR;
    secHdrsOff = INVALID_ADDR;
    optHdrOff = INVALID_ADDR;
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
    this->fHdr = (IMAGE_FILE_HEADER*) buf->getContentAt(offset, sizeof(pe::IMAGE_FILE_HEADER), allowExceptions);
    if (fHdr == NULL)  throw ExeException("Could not wrap PECore!");


    offset = offset + sizeof(pe::IMAGE_FILE_HEADER);
    WORD *magic = (WORD*) buf->getContentAt(offset, sizeof(WORD), allowExceptions);
    if (magic == NULL)  throw ExeException("Could not wrap PECore: invalid FileHeader");

    Executable::exe_bits mode = Executable::BITS_32;
    if ((*magic) == pe::OH_NT64) {//32 = 0x10B) {
        mode = Executable::BITS_64;
    }

    if (mode == Executable::BITS_32) {
        this->opt32 = (pe::IMAGE_OPTIONAL_HEADER32*) buf->getContentAt(offset, sizeof(pe::IMAGE_OPTIONAL_HEADER32), allowExceptions);

    } else if (mode == Executable::BITS_64) {
        this->opt64 = (pe::IMAGE_OPTIONAL_HEADER64*) buf->getContentAt(offset, sizeof(pe::IMAGE_OPTIONAL_HEADER64), allowExceptions);
    }
    if ( this->opt32 == NULL && this->opt64 == NULL) {
        throw ExeException("Could not wrap PECore : invalid OptionalHeader");
   }
   return true;
}

Executable::exe_bits PECore::getHdrBitMode()
{
    if (opt32) return Executable::BITS_32;
    if (opt64) return Executable::BITS_64;

    return Executable::BITS_32; // DEFAULT
}

offset_t PECore::peSignatureOffset()
{
    if (this->signatureOff == INVALID_ADDR)
        signatureOff = static_cast<offset_t> (dos->e_lfanew);
    return signatureOff;
}

offset_t PECore::peFileHdrOffset()
{
    if (this->fileHdrOff == INVALID_ADDR) {
        offset_t offset = peSignatureOffset();
        offset_t signSize = sizeof(DWORD);
        fileHdrOff = offset + signSize;
    }
    return fileHdrOff;

}

offset_t PECore::peOptHdrOffset()
{
    if (this->optHdrOff == INVALID_ADDR) {
        optHdrOff = peFileHdrOffset() + sizeof(IMAGE_FILE_HEADER);
    }
    return optHdrOff;
}

offset_t PECore::secHdrsOffset()
{
    if (this->secHdrsOff == INVALID_ADDR) {
        offset_t offset = peOptHdrOffset();
        offset_t size = static_cast<offset_t>(this->fHdr->SizeOfOptionalHeader);
        secHdrsOff = offset + size;
    }
    return secHdrsOff;
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
    offset_t imgSize = 0;
    if (this->opt32) {
        imgSize = opt32->SizeOfImage;
    }
    if (this->opt64) {
        imgSize = opt64->SizeOfImage;
    }
    return imgSize;
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

    //can be any value as long as ImageBase + 'SizeOfImage' < 80000000h
    //if the ImageBase is bigger than that, the binary will be relocated to 10000h
    offset_t maxOffset = this->getImageSize() + imgBase;
    if (maxOffset >= 0x80000000) {
        imgBase = DEFAULT_IMGBASE;
    }
    return imgBase;
}

