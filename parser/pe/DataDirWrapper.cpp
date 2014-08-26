#include "DataDirWrapper.h"
#include "PEFile.h"

using namespace pe;

void* DataDirWrapper::getPtr()
{
    if (m_PE == NULL) return NULL;

    offset_t myOff = m_PE->peDataDirOffset();
    pe::IMAGE_DATA_DIRECTORY* ptr = (pe::IMAGE_DATA_DIRECTORY*) m_Exe->getContentAt(myOff, getSize());
    return ptr;
}

bufsize_t DataDirWrapper::getSize()
{
    bufsize_t size = sizeof(pe::IMAGE_DATA_DIRECTORY) * DIRECTORY_ENTRIES_NUM;
    return size;
}

void* DataDirWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    if (fieldId >= DIRECTORY_ENTRIES_NUM) {
        return getPtr(); // invalid fieldID, give default
    }

    IMAGE_DATA_DIRECTORY* dataDir = (IMAGE_DATA_DIRECTORY*) getPtr();
    if (dataDir == NULL) return NULL;

    switch (subField) {
        case ADDRESS :
            return (void*)(&dataDir[fieldId].VirtualAddress);
        case SIZE :
            return (void*)(&dataDir[fieldId].Size);
    }
    return (void*)(&dataDir[fieldId].VirtualAddress);
}

bufsize_t DataDirWrapper::getFieldSize(size_t fieldId, size_t subField)
{
    if (fieldId >= DIRECTORY_ENTRIES_NUM) return getSize();

    pe::IMAGE_DATA_DIRECTORY* dir = (IMAGE_DATA_DIRECTORY*) getPtr();
    if (dir == NULL) return 0;

    pe::IMAGE_DATA_DIRECTORY record = dir[fieldId];

    switch (subField) {
        case ADDRESS :
            return sizeof(record.VirtualAddress);
        case SIZE :
            return sizeof(record.Size);
    }
    return sizeof(record.VirtualAddress) + sizeof(record.Size);
}

QString DataDirWrapper::getFieldName(size_t fieldId)
{
    switch (fieldId) {
        case DIR_EXPORT: return "Export Directory";
        case DIR_IMPORT: return "Import Directory";
        case DIR_RESOURCE : return "Resource Directory";
        case DIR_EXCEPTION: return "Exception Directory";
        case DIR_SECURITY: return "Security Directory";
        case DIR_BASERELOC: return "Base Relocation Table";
        case DIR_DEBUG : return "Debug Directory";
        case DIR_ARCHITECTURE: return "Architecture Specific Data";
        case DIR_GLOBALPTR : return "RVA of GlobalPtr";
        case DIR_TLS: return "TLS Directory";
        case DIR_LOAD_CONFIG: return "Load Configuration Directory";
        case DIR_BOUND_IMPORT: return "Bound Import Directory in headers";
        case DIR_IAT: return "Import Address Table";
        case DIR_DELAY_IMPORT: return "Delay Load Import Descriptors";
        case DIR_COM_DESCRIPTOR : return "COM Runtime descriptor";
    }
    return "";
}

Executable::addr_type DataDirWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    if (subField != ADDRESS) return Executable::NOT_ADDR;

    if (fieldId == DIR_SECURITY) return Executable::RAW;
    return Executable::RVA;
}
