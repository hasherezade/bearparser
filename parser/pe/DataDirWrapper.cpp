#include "pe/DataDirWrapper.h"
#include "pe/PEFile.h"

void* DataDirWrapper::getPtr()
{
    if (m_PE == NULL) return NULL;

    const offset_t myOff = m_PE->peDataDirOffset();
    IMAGE_DATA_DIRECTORY* ptr = (IMAGE_DATA_DIRECTORY*) m_Exe->getContentAt(myOff, getSize());
    return ptr;
}

bufsize_t DataDirWrapper::getSize()
{
    if (m_PE == NULL) return 0;
    const size_t count = getDirsCount();
    const bufsize_t size = sizeof(IMAGE_DATA_DIRECTORY) * count;
    return size;
}

size_t DataDirWrapper::getDirsCount()
{
    if (m_PE == NULL) return 0;
    OptHdrWrapper* optHdr  = dynamic_cast<OptHdrWrapper*>(m_PE->getWrapper(PEFile::WR_OPTIONAL_HDR));
    if (!optHdr) return 0;
    bool isOk = false;
    size_t count = optHdr->getNumValue(OptHdrWrapper::RVAS_SIZES_NUM, &isOk);
    if (!isOk) return 0;
    if (count > pe::DIR_ENTRIES_COUNT) {
        count = pe::DIR_ENTRIES_COUNT;
    }
    return count;
}

void* DataDirWrapper::getFieldPtr(size_t fieldId, size_t subField)
{
    if (fieldId >= getDirsCount()) {
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
    if (fieldId >= getDirsCount()) return getSize();

    IMAGE_DATA_DIRECTORY* dir = (IMAGE_DATA_DIRECTORY*) getPtr();
    if (dir == NULL) return 0;

    IMAGE_DATA_DIRECTORY record = dir[fieldId];

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
        case pe::DIR_EXPORT: return "Export Directory";
        case pe::DIR_IMPORT: return "Import Directory";
        case pe::DIR_RESOURCE : return "Resource Directory";
        case pe::DIR_EXCEPTION: return "Exception Directory";
        case pe::DIR_SECURITY: return "Security Directory";
        case pe::DIR_BASERELOC: return "Base Relocation Table";
        case pe::DIR_DEBUG : return "Debug Directory";
        case pe::DIR_ARCHITECTURE: return "Architecture Specific Data";
        case pe::DIR_GLOBALPTR : return "RVA of GlobalPtr";
        case pe::DIR_TLS: return "TLS Directory";
        case pe::DIR_LOAD_CONFIG: return "Load Configuration Directory";
        case pe::DIR_BOUND_IMPORT: return "Bound Import Directory";
        case pe::DIR_IAT: return "Import Address Table";
        case pe::DIR_DELAY_IMPORT: return "Delay Load Import Descriptors";
        case pe::DIR_COM_DESCRIPTOR : return ".NET header";
    }
    return "";
}

Executable::addr_type DataDirWrapper::containsAddrType(size_t fieldId, size_t subField)
{
    if (subField != ADDRESS) return Executable::NOT_ADDR;

    if (fieldId == pe::DIR_SECURITY) return Executable::RAW;
    return Executable::RVA;
}
