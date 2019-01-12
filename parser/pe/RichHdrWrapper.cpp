#include "RichHdrWrapper.h"
#include "PEFile.h"
#include <iostream>


bool RichHdrWrapper::wrap()
{
    this->richSign = m_PE->getRichHeaderSign();
    this->dansHdr = m_PE->getRichHeaderBgn(richSign);
    if (!this->richSign || !this->dansHdr) {
        this->compIdCounter = 0;
        return false;
    }
    this->compIdCounter = this->compIdCount();
    return true;
}

void* RichHdrWrapper::getPtr()
{
    if (!this->dansHdr) {
        wrap();
    }
    return (void*)this->dansHdr;
}

size_t RichHdrWrapper::compIdCount()
{
    if (!this->richSign || !this->dansHdr) {
        return 0;
    }
    const pe::RICH_DANS_HEADER dans_empty = { 0 };
    const bufsize_t dif = ((ULONGLONG)richSign - (ULONGLONG)dansHdr) - (sizeof(dans_empty.dansId) + sizeof(dans_empty.cPad));
    bufsize_t count = dif / sizeof(pe::RICH_COMP_ID);
    return (size_t) count;
}

bufsize_t RichHdrWrapper::getSize()
{
    if (!this->richSign || !this->dansHdr) {
        return 0;
    }
    const offset_t dansOffset = getOffset(this->dansHdr);
    const offset_t richOffset = getOffset(this->richSign);
    offset_t diff = richOffset - dansOffset;

    pe::RICH_SIGNATURE rich1 = { 0 };
    diff += sizeof(rich1);
    return diff;
}

size_t RichHdrWrapper::getFieldsCount()
{
    if (getSize() == 0) return 0;
    return this->compIdCounter + FIELD_COUNTER - 1;
}

void* RichHdrWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    if (!this->richSign || !this->dansHdr) {
        return 0;
    }

    const size_t cnt = this->compIdCounter - 1;
    switch (fieldId) {
         case DANS_ID: return (void*) &dansHdr->dansId;
         case CPAD0: return (void*) &dansHdr->cPad[0];
         case CPAD1: return (void*) &dansHdr->cPad[1];
         case CPAD2: return (void*) &dansHdr->cPad[2];
    }
    if (fieldId >= COMP_ID_1 && fieldId <= COMP_ID_1 + cnt)
    {
        size_t compIdNum = fieldId - COMP_ID_1;
        return (void*)(ULONGLONG(&dansHdr->compId) + (sizeof(pe::RICH_COMP_ID)*compIdNum));
    }
    if (fieldId == RICH_ID + cnt) return (void*) &richSign->richId;
    if (fieldId == CHECKSUM + cnt) return (void*) &richSign->checksum;
    return (void*) dansHdr;
}

bufsize_t RichHdrWrapper::getFieldSize(size_t fieldId, size_t subField)
{
    if (!this->richSign || !this->dansHdr) {
        return 0;
    }
    if (this->compIdCounter == 0) {
        return 0;
    }
    const size_t cnt = this->compIdCounter - 1;
    switch (fieldId) {
        case DANS_ID: 
            return sizeof(dansHdr->dansId);
        case CPAD0: 
        case CPAD1:
        case CPAD2:
            return sizeof(dansHdr->cPad[0]);
    }
    if (fieldId >= COMP_ID_1 && fieldId <= COMP_ID_1 + cnt)
    {
        return sizeof(pe::RICH_COMP_ID);
    }
    if (fieldId == RICH_ID + cnt) return sizeof(richSign->richId);
    if (fieldId == CHECKSUM + cnt) return sizeof(richSign->checksum);
    return 0;
}

QString RichHdrWrapper::getFieldName(size_t fieldId)
{
    if (!this->richSign || !this->dansHdr) {
        return "";
    }
    const size_t cnt = this->compIdCounter - 1;

    switch (fieldId) {
         case DANS_ID: return("DanS ID");
         case CPAD0: case CPAD1: case CPAD2:  return ("Checksumed padding");
    }
    if (fieldId >= COMP_ID_1 && fieldId <= COMP_ID_1 + cnt)
    {
        return("Comp ID");
    }
    if (fieldId == RICH_ID + cnt) return("Rich ID");
    if (fieldId == CHECKSUM + cnt) return("Checksum");
    return "";
}

pe::RICH_COMP_ID RichHdrWrapper::getCompId(size_t fieldId)
{
    pe::RICH_COMP_ID emptyId = { 0 };
    if (!this->richSign || !this->dansHdr) {
        return emptyId;
    }
    const uint32_t xorVal = this->richSign->checksum;
    const size_t cnt = this->compIdCounter - 1;
    bool isOk = false;
    uint64_t num = this->getNumValue(fieldId, &isOk);
    if (!isOk) {
        return emptyId;
    }
    if (fieldId >= COMP_ID_1 && fieldId <= COMP_ID_1 + cnt)
    {
        uint64_t xorVal2 = xorVal | ((uint64_t)xorVal << sizeof(uint32_t)*8);
        uint64_t my_num = static_cast<uint64_t>(num) ^ (xorVal2);
        pe::RICH_COMP_ID* myCompId = reinterpret_cast<pe::RICH_COMP_ID*>(&my_num);
        return *myCompId;
    }
    return emptyId;
}


inline DWORD rol32(DWORD temp, DWORD i)
{
    return ((temp << (i%32)) | (temp >> (32-(i%32))));
}

DWORD RichHdrWrapper::calcChecksum()
{
    BYTE *data = m_Exe->getContent();
    const size_t dataSize = m_Exe->getContentSize();
    const size_t dansOffset = getOffset(this->dansHdr);

    DWORD cksum = dansOffset;
    for (size_t i = 0; i < dansOffset && i < dataSize; i++) {
        //skip e_lfanew
        if (i >= 0x3c && i < 0x40) {
            continue;
        }
        BYTE temp = data[i];
        cksum += rol32(temp,i);
        cksum &= 0xffffffff;
    }
    size_t compKeys = compIdCount();
    for (size_t k = COMP_ID_1; k < (COMP_ID_1 + compKeys); k++) {
        pe::RICH_COMP_ID compId = this->getCompId(k);
        
        DWORD temp = compId.prodId << 16 | compId.CV;
        DWORD roled = rol32(temp, compId.count);
        cksum += roled;
        cksum &=0xffffffff;
    }
    return cksum;
}

Executable::addr_type RichHdrWrapper::containsAddrType(uint32_t fieldId, uint32_t subField)
{
    return Executable::NOT_ADDR;
}

QString RichHdrWrapper::translateFieldContent(size_t fieldId)
{
    if (!this->richSign || !this->dansHdr) {
        return "";
    }
    const uint32_t xorVal = this->richSign->checksum;
    const size_t cnt = this->compIdCounter - 1;

    bool isOk = false;
    uint64_t num = this->getNumValue(fieldId, &isOk);
    if (!isOk) {
        return "?";
    }
    switch (fieldId) {
        case DANS_ID:
        case CPAD0: case CPAD1: case CPAD2: {
            uint32_t my_num = static_cast<uint32_t>(num) ^ xorVal;
            if (my_num == pe::DANS_HDR_MAGIC) return "DanS";
            return QString::number(my_num, 16);
        }
    }
    if (fieldId >= COMP_ID_1 && fieldId <= COMP_ID_1 + cnt)
    {
        uint64_t xorVal2 = xorVal | ((uint64_t)xorVal << sizeof(uint32_t)*8);
        uint64_t my_num = static_cast<uint64_t>(num) ^ (xorVal2);
        pe::RICH_COMP_ID* myCompId = reinterpret_cast<pe::RICH_COMP_ID*>(&my_num);
        return QString::number(myCompId->CV, 10) + "." + QString::number(myCompId->prodId, 10) + "." + QString::number(myCompId->count, 10);
    }
    if (fieldId == RICH_ID + cnt) {
        if (static_cast<uint32_t>(num) == pe::RICH_HDR_MAGIC) return "Rich";
    }
    return "";
}
