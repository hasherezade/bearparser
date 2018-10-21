#include "RichHdrWrapper.h"
#include "PEFile.h"

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

void* RichHdrWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    RICH_SIGNATURE* richSign = m_PE->getRichHeaderSign();
    if (!richSign) {
        return nullptr;
    }
    RICH_DANS_HEADER* dansHdr = m_PE->getRichHeaderBgn(richSign);
    if (!dansHdr) {
        return nullptr;
    }
    switch (fieldId) {
         case DANS_ID: return (void*) &dansHdr->dansId;
         case CPAD: return (void*) &dansHdr->cPad;
         case COMP_ID_1: return (void*) &dansHdr->compId;
         case RICH_ID: return (void*) &richSign->richId;
         case CHECKSUM: return (void*) &richSign->checksum;
    }
    return (void*) dansHdr;
}

QString RichHdrWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
         case DANS_ID: return("DanS ID");
         case CPAD: return ("Checksumed padding");
         case COMP_ID_1: return("Comp ID");
         case RICH_ID: return("Rich ID");
         case CHECKSUM: return("Checksum");
    }
    return "";
}

bufsize_t RichHdrWrapper::getFieldSize(size_t fieldId, size_t subField)
{
    switch (fieldId) {
         case DANS_ID: return sizeof(DWORD);
         case RICH_ID: return sizeof(DWORD);
         case CHECKSUM: return sizeof(DWORD);
    }
    return PEElementWrapper::getFieldSize(fieldId, subField);
}

Executable::addr_type RichHdrWrapper::containsAddrType(uint32_t fieldId, uint32_t subField)
{
    return Executable::NOT_ADDR;
}
