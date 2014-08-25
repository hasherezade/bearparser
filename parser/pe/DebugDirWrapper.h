#pragma once

#include "DataDirEntryWrapper.h"

class DebugDirWrapper : public DataDirEntryWrapper
{
public:

    enum DebugDirFID {
        NONE = FIELD_NONE,
        CHARACTERISTIC,
        TIMESTAMP,
        MAJOR_VER,
        MINOR_VER,
        TYPE,
        DATA_SIZE,
        RAW_DATA_ADDR,
        RAW_DATA_PTR,
        FIELD_COUNTER
    };

    DebugDirWrapper(PEFile *pe)
        : DataDirEntryWrapper(pe, pe::DIR_DEBUG) { wrap(); }

    ~DebugDirWrapper() { clear(); }

    bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    QString translateType(int type);
    QString translateFieldContent(size_t fieldId);

private:
    pe::IMAGE_DEBUG_DIRECTORY* debugDir();

    void clear() {}
};

