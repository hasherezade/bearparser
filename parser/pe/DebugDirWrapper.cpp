#include "DebugDirWrapper.h"
#include "PEFile.h"

using namespace pe;
/*
typedef struct _IMAGE_DEBUG_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Type;
    DWORD   SizeOfData;
    DWORD   AddressOfRawData;
    DWORD   PointerToRawData;
} IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

*/

pe::IMAGE_DEBUG_DIRECTORY* DebugDirWrapper::debugDir()
{
    offset_t rva = getDirEntryAddress();

    BYTE *ptr = m_Exe->getContentAt(rva, Executable::RVA, sizeof(pe::IMAGE_DEBUG_DIRECTORY));
    if (ptr == NULL) return NULL;

    return (pe::IMAGE_DEBUG_DIRECTORY*) ptr;
}

bool DebugDirWrapper::wrap()
{
    return true;
}

void* DebugDirWrapper::getPtr()
{
    return debugDir();
}

bufsize_t DebugDirWrapper::getSize()
{
    if (getPtr() == NULL) return 0;
    return sizeof(pe::IMAGE_DEBUG_DIRECTORY);
}

QString DebugDirWrapper::getName()
{
    return "Debug";
}


void* DebugDirWrapper::getFieldPtr(size_t fId, size_t subField)
{
    pe::IMAGE_DEBUG_DIRECTORY* d = debugDir();
    if (d == NULL) return NULL;

    switch (fId) {
        case CHARACTERISTIC: return &d->Characteristics;
        case TIMESTAMP: return &d->TimeDateStamp;
        case MAJOR_VER: return &d->MajorVersion;
        case MINOR_VER: return &d->MinorVersion;
        case TYPE: return &d->Type;
        case DATA_SIZE: return &d->SizeOfData;
        case RAW_DATA_ADDR: return &d->AddressOfRawData;
        case RAW_DATA_PTR: return &d->PointerToRawData;
    }
    return this->getPtr();
}

QString DebugDirWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case CHARACTERISTIC: return "Characteristics";
        case TIMESTAMP: return "TimeDateStamp";
        case MAJOR_VER: return "MajorVersion";
        case MINOR_VER: return "MinorVersion";
        case TYPE: return "Type";
        case DATA_SIZE: return "SizeOfData";
        case RAW_DATA_ADDR: return "AddressOfRawData";
        case RAW_DATA_PTR: return "PointerToRawData";
    }
    return getName();
}

Executable::addr_type DebugDirWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    switch (fieldId) {
        case RAW_DATA_ADDR: return Executable::RVA;
        case RAW_DATA_PTR: return Executable::RAW;
    }
    return Executable::NOT_ADDR;
}

QString DebugDirWrapper::translateType(int type)
{
    switch (type) {
        case pe::DT_UNKNOWN : return "unknown";
        case pe::DT_COFF : return "COFF";
        case pe::DT_CODEVIEW : return "Visual C++";
        case pe::DT_FPO : return "frame pointer omission";
        case pe::DT_MISC : return "DBG file";
        case pe::DT_EXCEPTION : return "A copy of .pdata section";
        case pe::DT_FIXUP : return "Reserved";
        case pe::DT_OMAP_TO_SRC : return "mapping from an RVA in image to an RVA in source image";
        case pe::DT_OMAP_FROM_SRC : return "mapping from an RVA in source image to an RVA in image";
        case pe::DT_BORLAND : return "Borland";
        case pe::DT_RESERVED10 : return "Reserved";
        case pe::DT_CLSID : return "CLSID";
    }
    return "";
}

