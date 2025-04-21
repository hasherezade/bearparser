#pragma once

#include "../Executable.h"
#include "pe_formats.h"

//class for internal use of PEFile
class PECore
{
public:

    PECore()
        : buf(NULL), dos(NULL), fHdr(NULL), opt32(NULL), opt64(NULL) {}

    virtual ~PECore()
    {
        reset();
    }

    bool wrap(AbstractByteBuffer *v_buf);

    virtual offset_t getRawSize() const { return buf ? static_cast<offset_t>(buf->getContentSize()) : 0; }

    virtual bufsize_t getAlignment(Executable::addr_type aType) const;
    virtual offset_t getImageBase(bool recalculate = false);
    virtual bufsize_t getImageSize();

    Executable::exe_bits getHdrBitMode() const;
    Executable::exe_arch getHdrArch() const;
    offset_t peSignatureOffset() const;
    offset_t peFileHdrOffset() const;
    offset_t secHdrsOffset() const;
    offset_t peOptHdrOffset() const;
    bufsize_t peNtHeadersSize() const;
    bufsize_t hdrsSize() const;

    void setImageSize(bufsize_t newSize)
    {
        if (this->opt32) {
            this->opt32->SizeOfImage = MASK_TO_DWORD(newSize);
        }
        else if (this->opt64) {
            this->opt64->SizeOfImage = MASK_TO_DWORD(newSize);
        }
    }

    IMAGE_FILE_HEADER *getFileHeader() const
    {
        return fHdr;
    }

protected:
    void reset();
    AbstractByteBuffer *buf;

    IMAGE_DOS_HEADER *dos;
    IMAGE_FILE_HEADER* fHdr;
    IMAGE_OPTIONAL_HEADER32* opt32;
    IMAGE_OPTIONAL_HEADER64* opt64;

friend class PEFile;
};

