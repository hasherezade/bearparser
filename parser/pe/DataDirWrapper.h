#pragma once

#include "PENodeWrapper.h"

using namespace pe;

class DataDirWrapper : public ExeElementWrapper
{
public:
    enum DataDirSID {
        NONE = FIELD_NONE,
        ADDRESS = 0,
        SIZE = 1,
        COUNTER
    };

    DataDirWrapper(Executable *pe) : ExeElementWrapper(pe) {}
    virtual size_t getSubFieldsCount() { return 2; }

    /* full structure boundatries */
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "Data Directory"; }
    virtual size_t getFieldsCount() { return DIRECTORY_ENTRIES_NUM; }

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

friend class PEFile;
};
