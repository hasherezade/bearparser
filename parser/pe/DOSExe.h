#pragma once

#include "../MappedExe.h"
#include "DosHdrWrapper.h"

#define DOS_PARAGRAPH 0x10


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
    virtual offset_t rawToRva(offset_t raw) { return raw - codeOffset(); } //TODO
    virtual offset_t rvaToRaw(offset_t rva) { return rva + codeOffset();  } //TODO

    virtual bufsize_t getMappedSize(Executable::addr_type aType) { return this->getContentSize(); }//TODO
    virtual bufsize_t getAlignment(Executable::addr_type aType) { return 0; } //TODO
    virtual offset_t getImageBase() { return m_dosHdr->e_cs; } //TODO
    virtual offset_t getEntryPoint(Executable::addr_type aType = Executable::RVA) { return codeOffset() + m_dosHdr->e_ip; } //TODO

    Executable::addr_type detectAddrType(offset_t addr, Executable::addr_type hintType) { return Executable::RAW; }
    //---
    // DOS Exe only:
    virtual offset_t dosHeaderOffset() { return 0; } //wrapper's mount point
    offset_t peSignatureOffset();

protected:
    offset_t codeOffset() { return static_cast<offset_t> (m_dosHdr->e_cparhdr) * DOS_PARAGRAPH; }
    virtual void wrap(AbstractByteBuffer *v_buf);

    DosHdrWrapper *dosHdrWrapper;
    IMAGE_DOS_HEADER* m_dosHdr;
};

