#include "DataDirEntryWrapper.h"
#include "PEFile.h"

using namespace pe;

DataDirEntryWrapper::DataDirEntryWrapper(PEFile* pe, pe:: dir_entry v_entryType)
    :  PENodeWrapper(pe), entryType(v_entryType)
{
    wrap();
}

pe::IMAGE_DATA_DIRECTORY* DataDirEntryWrapper::getDataDirectory()
{

    if (m_PE == NULL) return NULL;

    IMAGE_DATA_DIRECTORY *d = m_PE->getDataDirectory();
    return d;
}

offset_t DataDirEntryWrapper::getDirEntryAddress()
{
    if (this->entryType >= pe::DIR_ENTRIES_COUNT) return INVALID_ADDR;

    IMAGE_DATA_DIRECTORY *d = getDataDirectory();
    if (!d) return INVALID_ADDR;

    offset_t rva = static_cast<offset_t>(d[this->entryType].VirtualAddress);
    if (rva == 0) return INVALID_ADDR;
    return rva;
}

bufsize_t DataDirEntryWrapper::getDirEntrySize()
{
    if (this->entryType >= pe::DIR_ENTRIES_COUNT) return 0;

    IMAGE_DATA_DIRECTORY *d = getDataDirectory();
    if (!d) return 0;

    bufsize_t size = static_cast<bufsize_t>(d[this->entryType].Size);
    return size;
}
