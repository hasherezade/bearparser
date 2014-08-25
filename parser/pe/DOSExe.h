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

    // inherited from Executable:
    //
    // FileAddr <-> RVA
    virtual offset_t fileAddrToRva(offset_t raw) { return raw; } //TODO
    virtual offset_t rvaToFileAddr(offset_t rva) { return rva; } //TODO

    virtual bufsize_t getMappedSize(Executable::addr_type aType) { return this->getContentSize(); }
    virtual bufsize_t getAlignment(Executable::addr_type aType) { return 0x1000; } //TODO
    virtual offset_t getImageBase() { return 0; } //TODO
    virtual offset_t getEntryPoint() { return 0; } //TODO

    Executable::addr_type detectAddrType(offset_t addr, Executable::addr_type hintType) { return Executable::RAW; }
    //---
    // DOS Exe only:
    virtual offset_t dosHeaderOffset() { return 0; } //wrapper's mount point
    offset_t peSignatureOffset();

protected:
    virtual void wrap(AbstractByteBuffer *v_buf);

    DosHdrWrapper *dosHdrWrapper;
};

