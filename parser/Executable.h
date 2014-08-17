#pragma once
#include <map>

#include "AbstractByteBuffer.h"
class Executable;

class ExeException : public CustomException
{
public:
    ExeException(const QString info) : CustomException(info) {}
};

class ExeBuilder {
public:
    ExeBuilder() {}
    virtual ~ExeBuilder() {}

    virtual bool signatureMatches(AbstractByteBuffer *buf) = 0;
    virtual Executable* build(AbstractByteBuffer *buf) = 0;
};

//-------------------------------------------------------------

class Executable : public AbstractByteBuffer {
public:
    enum exe_bits {
        UNKNOWN = 0,
        BITS_16 = 16,
        BITS_32 = 32,
        BITS_64 = 64,
    };

    enum addr_type {
        NOT_ADDR = 0,
        RAW = 1,
        RVA = 2,
        VA = 3
    };
    virtual ~Executable(void) {}

    virtual exe_bits getBitMode() { return this->bitMode; }

    virtual bufsize_t getContentSize() { return buf->getContentSize(); }
    virtual BYTE* getContent() { return buf->getContent(); }
    //wrapper:
    virtual offset_t getRawSize() const { return static_cast<offset_t>(buf->getContentSize()); }

    BYTE* getContentAtPtr(BYTE* ptr, bufsize_t size, bool allowExceptions = false) { return AbstractByteBuffer::getContentAtPtr(ptr, size, allowExceptions); }
    BYTE* getContentAt(offset_t offset, bufsize_t size, bool allowExceptions = false) { return AbstractByteBuffer::getContentAt(offset, size, allowExceptions); }

    virtual BYTE* getContentAt(offset_t offset, Executable::addr_type aType, bufsize_t size, bool allowExceptions = false);
//------------------------------
    virtual bufsize_t getMappedSize(Executable::addr_type aType) = 0;
    virtual bufsize_t getAlignment(Executable::addr_type aType) = 0;
    virtual offset_t getImageBase() = 0;
    virtual offset_t getEntryPoint() = 0;

    /* conversions */
    virtual bool isValidAddr(offset_t addr, addr_type addrType);
    virtual bool isValidVA(offset_t va); // wrapper

    virtual offset_t convertAddr(offset_t inAddr, Executable::addr_type inType, Executable::addr_type outType);

    virtual offset_t toRaw(offset_t offset, addr_type addrType, bool allowExceptions = false); //any type of offset to raw
    Executable::addr_type detectAddrType(offset_t addr, Executable::addr_type hintType); //TODO

    // returns INVALID_ADDR if failed
    virtual offset_t fileAddrToRva(offset_t raw, bool getClosestIfInCave = false) = 0;

    virtual offset_t VaToRva(offset_t va, bool autodetect);
    virtual offset_t VaToFileAddr(offset_t rva, bool getClosestIfInCave = false) = 0;
    virtual offset_t rvaToFileAddr(offset_t rva, bool getClosestIfInCave = false) = 0;
    virtual offset_t rvaToVa(offset_t rva) = 0;

protected:
    Executable(AbstractByteBuffer *v_buf, exe_bits v_bitMode);

    exe_bits bitMode;
    AbstractByteBuffer *buf;
};

