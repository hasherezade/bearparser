#pragma once

#include "PENodeWrapper.h"

class PEFile;

using namespace pe;


class DataDirEntryWrapper : public PENodeWrapper
{
public:
    pe::IMAGE_DATA_DIRECTORY* getDataDirectory();

    offset_t getDirEntryAddress();
    bufsize_t getDirEntrySize();
    pe:: dir_entry getDirEntryType() { return this->entryType; }

protected:
    DataDirEntryWrapper(PEFile* pe, pe:: dir_entry v_entryType);

    pe::dir_entry entryType;
};

