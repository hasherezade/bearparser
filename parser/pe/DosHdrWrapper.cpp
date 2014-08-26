#include "DosHdrWrapper.h"
#include "DOSExe.h"

void* DosHdrWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
/*
    DOSExe *dosExe = dynamic_cast<DOSExe*> (m_Exe);
    if (dosExe == NULL) return NULL;
*/
    offset_t myOff = 0;//dosExe->dosHeaderOffset();
    IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*) m_Exe->getContentAt(myOff, sizeof(IMAGE_DOS_HEADER));
    if (dosHdr == NULL) return NULL; //error

    switch (fieldId) {
        case MAGIC: return (void*) &dosHdr->e_magic;
        case CBLP: return (void*) &dosHdr->e_cblp;
        case CP: return (void*) &dosHdr->e_cp;
        case CRLC: return (void*) &dosHdr->e_crlc;
        case CPARHDR: return (void*) &dosHdr->e_cparhdr;
        case MINALLOC: return (void*) &dosHdr->e_minalloc;
        case MAXALLOC: return (void*) &dosHdr->e_maxalloc;
        case SS: return (void*) &dosHdr->e_ss;
        case SP: return (void*) &dosHdr->e_sp;
        case CSUM: return (void*) &dosHdr->e_csum;
        case IP: return (void*) &dosHdr->e_ip;
        case CS: return (void*) &dosHdr->e_cs;
        case LFARLC: return (void*) &dosHdr->e_lfarlc;
        case OVNO: return (void*) &dosHdr->e_ovno;
        case RES: return (void*) &dosHdr->e_res[0];
        case OEMID: return (void*) &dosHdr->e_oemid;
        case OEMINFO: return (void*) &dosHdr->e_oeminfo;
        case RES2: return (void*) &dosHdr->e_res2[0];
        case LFNEW: return (void*) &dosHdr->e_lfanew;
        case FIELD_COUNTER: return (void*) (&dosHdr->e_lfanew + 1);
    }
    return (void*)dosHdr;
}

QString DosHdrWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case MAGIC: return "Magic number";
        case CBLP: return "Bytes on last page of file";
        case CP: return "Pages in file";
        case CRLC: return "Relocations";
        case CPARHDR: return "Size of header in paragraphs";
        case MINALLOC: return "Minimum extra paragraphs needed";
        case MAXALLOC: return "Maximum extra paragraphs needed";
        case SS: return "Initial (relative) SS value";
        case SP: return "Initial SP value";
        case CSUM: return "Checksum";
        case IP: return "Initial IP value";
        case CS: return "Initial (relative) CS value";
        case LFARLC: return "File address of relocation table";
        case OVNO: return "Overlay number";
        case RES: return "Reserved words[4]";
        case OEMID: return "OEM identifier (for OEM information)";
        case OEMINFO: return "OEM information; OEM identifier specific";
        case RES2: return "Reserved words[10]";
        case LFNEW: return "File address of new exe header";
    }
    return "";
}

Executable::addr_type DosHdrWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case LFARLC: return Executable::RAW;
        case LFNEW: return Executable::RAW;
    }
    return Executable::NOT_ADDR;
}

