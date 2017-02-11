#pragma once

#include "../Executable.h"
#include "pe_formats.h"

//class for internal use of PEFile
class PECore
{
public:

    PECore()
        : buf(NULL), dos(NULL), fHdr(NULL), opt32(NULL), opt64(NULL),
            signatureOff(INVALID_ADDR),
            fileHdrOff(INVALID_ADDR),
            secHdrsOff(INVALID_ADDR),
            optHdrOff(INVALID_ADDR)
            {}

    virtual ~PECore() {}

    bool wrap(AbstractByteBuffer *v_buf);

    virtual offset_t getRawSize() const { return static_cast<offset_t>(buf->getContentSize()); }

    virtual bufsize_t getAlignment(Executable::addr_type aType);
    virtual offset_t getImageBase();
    virtual bufsize_t getImageSize();

    Executable::exe_bits getHdrBitMode();
    offset_t peSignatureOffset();
    offset_t peFileHdrOffset();
    offset_t secHdrsOffset();
    offset_t peOptHdrOffset();
    bufsize_t hdrsSize();

protected:
    void reset();
    AbstractByteBuffer *buf;

    IMAGE_DOS_HEADER *dos;
    IMAGE_FILE_HEADER* fHdr;
    IMAGE_OPTIONAL_HEADER32* opt32;
    IMAGE_OPTIONAL_HEADER64* opt64;
//cached:
    offset_t signatureOff;
    offset_t fileHdrOff;
    offset_t secHdrsOff;
    offset_t optHdrOff;

friend class PEFile;
};

