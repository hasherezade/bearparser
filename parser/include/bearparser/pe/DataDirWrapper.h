#pragma once

#include "PENodeWrapper.h"

class DataDirWrapper : public PEElementWrapper
{
public:
    enum DataDirSID {
        NONE = FIELD_NONE,
        ADDRESS = 0,
        SIZE = 1,
        COUNTER
    };

    DataDirWrapper(PEFile *pe) : PEElementWrapper(pe) {}
    virtual size_t getSubFieldsCount() { return COUNTER; }

    /* full structure boundaries */
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "Data Directory"; }
    virtual size_t getFieldsCount() { return pe::DIR_ENTRIES_COUNT; }

    /* specific field boundaries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

};
