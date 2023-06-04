#include "pe/DataDirEntryWrapper.h"
#include "pe/PEFile.h"

DataDirEntryWrapper::DataDirEntryWrapper(PEFile* pe, pe:: dir_entry v_entryType)
    :  PENodeWrapper(pe), entryType(v_entryType)
{
    wrap();
}

IMAGE_DATA_DIRECTORY* DataDirEntryWrapper::getDataDirectory()
{

    if (m_PE == NULL) return NULL;

    IMAGE_DATA_DIRECTORY *d = m_PE->getDataDirectory();
    return d;
}

offset_t DataDirEntryWrapper::getDirEntryAddress()
{
    DataDirWrapper *dDir = dynamic_cast<DataDirWrapper*>(m_PE->getWrapper(PEFile::WR_DATADIR));
    const size_t recordsCount = dDir ? dDir->getDirsCount() : 0;
    if (this->entryType >= recordsCount) return INVALID_ADDR;

    IMAGE_DATA_DIRECTORY *d = getDataDirectory();
    if (!d) return INVALID_ADDR;

    offset_t rva = static_cast<offset_t>(d[this->entryType].VirtualAddress);
    if (rva == 0) return INVALID_ADDR;
    return rva;
}

bufsize_t DataDirEntryWrapper::getDirEntrySize(bool trimToExeSize)
{
    DataDirWrapper *dDir = dynamic_cast<DataDirWrapper*>(m_PE->getWrapper(PEFile::WR_DATADIR));
    const size_t recordsCount = dDir ? dDir->getDirsCount() : 0;
    if (this->entryType >= recordsCount) return 0;
    
    IMAGE_DATA_DIRECTORY *d = getDataDirectory();
    if (!d) return 0;
    
    bufsize_t dirSize = static_cast<bufsize_t>(d[this->entryType].Size);
    if (!trimToExeSize) {
        return dirSize;
    }
    
    if (!this->m_Exe) return 0; // should never happen
    
    offset_t dirRva = d[this->entryType].VirtualAddress;
    offset_t dirRaw = this->m_Exe->rvaToRaw(dirRva);
    if (dirRaw == INVALID_ADDR) {
        return 0;
    }
    bufsize_t fullSize = this->m_Exe->getContentSize();
    bufsize_t remainingSize = bufsize_t(fullSize - dirRaw);
    
    return (dirSize < remainingSize) ? dirSize : remainingSize;
}
