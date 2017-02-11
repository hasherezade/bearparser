#pragma once

#include "PENodeWrapper.h"

class PEFile;


class DataDirEntryWrapper : public PENodeWrapper
{
public:
    IMAGE_DATA_DIRECTORY* getDataDirectory();

    offset_t getDirEntryAddress();
    bufsize_t getDirEntrySize();
    int getDirEntryType() { return this->entryType; }

protected:
    DataDirEntryWrapper(PEFile* pe, pe:: dir_entry v_entryType);

    int entryType;

friend class PEFile;
};

