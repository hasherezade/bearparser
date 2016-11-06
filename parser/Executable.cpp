#include "Executable.h"
#include "FileBuffer.h"

Executable::Executable(AbstractByteBuffer *v_buf, exe_bits v_bitMode)
    : buf(v_buf), bitMode(v_bitMode)
{
    if (v_buf == NULL) throw ExeException("Cannot make Exe from NULL buffer");
    FileBuffer *fileBuf = dynamic_cast<FileBuffer*>(buf);
    if (fileBuf) {
        this->fileName = fileBuf->getFileName();
    }
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

    const offset_t imgBase = this->getImageBase();

    if (outType == Executable::RAW) {
        if (inType == Executable::VA) {
            if (inAddr < imgBase) return INVALID_ADDR;
            inAddr = inAddr - imgBase;
            inType = Executable::RVA;
        }
        return this->rvaToRaw(inAddr);
    }
    if (inType == Executable::RAW) {
        offset_t out = this->rawToRva(inAddr);
        if (out == INVALID_ADDR) return INVALID_ADDR;

        if (outType == Executable::VA) {
            return out + imgBase;
        }
        return out;
    }
    if (outType == Executable::RVA) {
        if (inAddr < imgBase) return INVALID_ADDR;
        return inAddr - imgBase;
    }
    if (outType == Executable::VA) {
        return inAddr + imgBase;
    }
    return INVALID_ADDR;
}

offset_t Executable::toRaw(offset_t offset, addr_type aT, bool allowExceptions)
{
    if (offset == INVALID_ADDR) {
        return INVALID_ADDR;
    }

    offset_t convertedOffset = INVALID_ADDR;

    if (aT == Executable::RAW) {
        //no need to convert
        convertedOffset = offset;
    } else if (aT == Executable::VA) {
        convertedOffset = VaToRva(offset, false);
    } else if (aT == Executable::RVA){
        try {
            convertedOffset = this->rvaToRaw(offset);
        } catch (CustomException e) {
            if (allowExceptions) throw e;
        }  
    }
    //---
    if (convertedOffset == INVALID_ADDR) {
        Logger::append(Logger::WARNING,
            "Address out of bounds: offset = %llX addrType = %u",
            static_cast<unsigned long long>(offset),
            static_cast<unsigned int>(aT)
        );
        if (allowExceptions) throw CustomException("Address out of bounds!");
    }
    //---
    return convertedOffset;
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

