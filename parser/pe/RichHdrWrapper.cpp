#include "RichHdrWrapper.h"
#include "PEFile.h"
#include <iostream>

bool RichHdrWrapper::wrap()
{
    this->richSign = m_PE->getRichHeaderSign();
    this->dansHdr = m_PE->getRichHeaderBgn(richSign);
    this->compIdCounter = this->compIdCount();
    return true;
}


void* RichHdrWrapper::getPtr()
{
    RICH_SIGNATURE* richSign = m_PE->getRichHeaderSign();
    if (!richSign) {
        return nullptr;
    }
    RICH_DANS_HEADER* dansHdr = m_PE->getRichHeaderBgn(richSign);
    if (!dansHdr) {
        return nullptr;
    }
    return (void*)dansHdr;
}

size_t RichHdrWrapper::compIdCount()
{
    if (!this->richSign || !this->dansHdr) {
        return 0;
    }
    const RICH_DANS_HEADER dans_empty = { 0 };
    const bufsize_t dif = ((ULONGLONG)richSign - (ULONGLONG)dansHdr) - (sizeof(dans_empty.dansId) + sizeof(dans_empty.cPad));
    bufsize_t count = dif / sizeof(RICH_COMP_ID);
    return (size_t) count;
}

bufsize_t RichHdrWrapper::getSize()
{
    if (!this->richSign || !this->dansHdr) {
        return 0;
    }
    const size_t cnt = this->compIdCounter - 1;
    const bufsize_t dif = sizeof(RICH_DANS_HEADER) + sizeof(RICH_SIGNATURE) + (sizeof(RICH_COMP_ID) * cnt);
    return dif;
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
         case CPAD: return (void*) &dansHdr->cPad;
         case COMP_ID_1: return (void*) &dansHdr->compId;
         //case RICH_ID: return (void*) &richSign->richId;
         //case CHECKSUM: return (void*) &richSign->checksum;
    }
    if (fieldId > COMP_ID_1 && fieldId <= COMP_ID_1 + cnt)
    {
        size_t compIdNum = fieldId - COMP_ID_1;
        return (void*)(ULONGLONG(&dansHdr->compId) + (sizeof(RICH_COMP_ID)*compIdNum));
    }
    if (fieldId == RICH_ID + cnt) return (void*) &richSign->richId;
    if (fieldId == CHECKSUM + cnt) return (void*) &richSign->checksum;
    return (void*) dansHdr;
}

QString RichHdrWrapper::getFieldName(size_t fieldId)
{
    if (!this->richSign || !this->dansHdr) {
        return "";
    }
    const size_t cnt = this->compIdCounter - 1;

    switch (fieldId) {
         case DANS_ID: return("DanS ID");
         case CPAD: return ("Checksumed padding");
         case COMP_ID_1: return("Comp ID");
         //case RICH_ID: return("Rich ID");
         //case CHECKSUM: return("Checksum");
    }
    if (fieldId > COMP_ID_1 && fieldId <= COMP_ID_1 + cnt)
    {
        return("Comp ID");
    }
    if (fieldId == RICH_ID + cnt) return("Rich ID");
    if (fieldId == CHECKSUM + cnt) return("Checksum");
    return "";
}

Executable::addr_type RichHdrWrapper::containsAddrType(uint32_t fieldId, uint32_t subField)
{
    return Executable::NOT_ADDR;
}
