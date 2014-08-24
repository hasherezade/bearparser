#pragma once

#include "../ExeNodeWrapper.h"
#include "pe_formats.h"

using namespace pe;

class DataDirEntryWrapper : public ExeNodeWrapper
{
public:
    pe::IMAGE_DATA_DIRECTORY* getDataDirectory();

    offset_t getDirEntryAddress();
    bufsize_t getDirEntrySize();
    pe:: dir_entry getDirEntryType() { return this->entryType; }

protected:
    DataDirEntryWrapper(Executable* pe, pe:: dir_entry v_entryType)
        :  ExeNodeWrapper(pe), entryType(v_entryType)
    {
        wrap();
    }

    pe:: dir_entry entryType;
};

