#include "Executable.h"

Executable::Executable(AbstractByteBuffer *v_buf, exe_bits v_bitMode)
    : buf(v_buf), bitMode(v_bitMode)
{
    if (v_buf == NULL) throw ExeException("Cannot make Exe from NULL buffer");
}

BYTE* Executable::getContentAt(offset_t offset, Executable::addr_type aType, bufsize_t size, bool allowExceptions)
{
    offset_t raw = this->toRaw(offset, aType, allowExceptions);
    if (raw == INVALID_ADDR) {
        return NULL;
    }
    BYTE *cAt = AbstractByteBuffer::getContentAt(raw, size, allowExceptions);
    return cAt;
}

bool Executable::isValidAddr(offset_t addr, addr_type addrType)
{
    offset_t mappedFrom = (addrType == Executable::VA) ? this->getImageBase() : 0;
    offset_t mappedTo = mappedFrom + this->getMappedSize(addrType);

   return (addr >= mappedFrom && addr < mappedTo) ? true : false;
}

offset_t Executable::VaToRva(offset_t va, bool autodetect)
{
    offset_t mappedFrom = this->getImageBase();
    offset_t mappedTo = mappedFrom + this->getMappedSize(Executable::RVA);

    if (autodetect && !isValidAddr(va, Executable::VA)) {
        return va;
    }
    if (va < mappedFrom) return va;

    offset_t rva = va - mappedFrom;
    return rva;
}

offset_t Executable::convertAddr(offset_t inAddr, Executable::addr_type inType, Executable::addr_type outType)
{
    if (inType == Executable::NOT_ADDR || outType == Executable::NOT_ADDR ) {
        return INVALID_ADDR;
    }
    if (!isValidAddr(inAddr, inType)) {
        return INVALID_ADDR;
    }
    if (inType == outType) return inAddr;
    if (inType == Executable::RAW && outType == Executable::RVA) {
        return this->fileAddrToRva(inAddr);
    }
    if (inType == Executable::RAW && outType == Executable::VA) {
        return this->fileAddrToRva(inAddr) + this->getImageBase();
    }
    if (outType == Executable::RAW) {
        bool allowExceptions = false;
        return toRaw(inAddr, inType, allowExceptions);
    }
    return INVALID_ADDR;
}

offset_t Executable::toRaw(offset_t offset, addr_type aT, bool allowExceptions)
{
    if (offset == INVALID_ADDR) return INVALID_ADDR;

    if (this->isValidAddr(offset, aT) == false) {
        if (DBG_LVL) printf("Address out of bounds: offset = %llX addrType = %d\n", offset, aT);
        if (allowExceptions) throw CustomException("Address out of bounds!");
        return INVALID_ADDR;
    }

    if (aT == Executable::RAW) {
        //no need to convert
        return offset;
    }

    if (aT == Executable::VA) {
        offset = VaToRva(offset, false);
    }
    try {
        offset = this->rvaToFileAddr(offset);
    } catch (CustomException e) {
        if (allowExceptions) throw e;
        return INVALID_ADDR;
    }
    return offset;
}

Executable::addr_type Executable::detectAddrType(offset_t offset, Executable::addr_type hintType)
{
    if (hintType == Executable::RAW) {
        if (this->isValidAddr(offset, hintType) == false) {
            return Executable::NOT_ADDR;
        } else return hintType; // it is RAW
    }

    if (hintType == Executable::NOT_ADDR) {
        hintType = Executable::RVA; // check RVA by default
    }
    if (this->isValidAddr(offset, hintType) == false) {
        if (hintType == Executable::RVA) {
            hintType = Executable::VA; // if not RVA, try VA
        } else {
            hintType = Executable::RVA; // if not VA, try RVA
        }
    }
    if (this->isValidAddr(offset, hintType) == false) {
        return Executable::NOT_ADDR; //every attempt failed! it's invalid!
    }
    return hintType;
}

