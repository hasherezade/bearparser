#pragma once

#include "../MappedExe.h"
#include "DosHdrWrapper.h"


class DOSExeBuilder: public ExeBuilder {
public:
    DOSExeBuilder() : ExeBuilder() {}
    virtual bool signatureMatches(AbstractByteBuffer *buf);
    virtual Executable* build(AbstractByteBuffer *buf);
    QString typeName() { return "MZ"; }
};

//-------------------------------------------------------------

class DOSExe : public MappedExe
{
public:
    enum WRAPPERS {
        WR_NONE = MappedExe::WR_NONE,
        WR_DOS_HDR = 0,
        COUNT_WRAPPERS
    };

    DOSExe(AbstractByteBuffer *v_buf);
    virtual ~DOSExe() { TRACE(); }

    virtual bufsize_t getMappedSize(Executable::addr_type aType) { return this->getContentSize(); }
    virtual bufsize_t getAlignment(Executable::addr_type aType) { return 0x1000; } //TODO
    virtual offset_t getImageBase() { return 0; } //TODO
    virtual offset_t getEntryPoint() { return 0; } //TODO

    virtual offset_t dosHeaderOffset() { return 0; } //wrapper's mount point
    Executable::addr_type detectAddrType(offset_t addr, Executable::addr_type hintType) { return Executable::RAW; }

    // returns INVALID_ADDR if failed
    virtual offset_t fileAddrToRva(offset_t raw, bool getClosestIfInCave = false) { return raw; }

    virtual offset_t VaToRva(offset_t va, bool autodetect = true) const { return va; }
    virtual offset_t VaToFileAddr(offset_t rva, bool getClosestIfInCave = false) { return rva; }
    virtual offset_t rvaToFileAddr(offset_t rva, bool getClosestIfInCave = false) { return rva; }
    virtual offset_t rvaToVa(offset_t rva) { return rva; }

    offset_t peSignatureOffset();

protected:
    virtual void wrap(AbstractByteBuffer *v_buf);

    DosHdrWrapper *dosHdrWrapper;
};

