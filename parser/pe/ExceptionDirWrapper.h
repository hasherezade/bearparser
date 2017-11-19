#pragma once

#include "DataDirEntryWrapper.h"

class ExceptionEntryWrapper;
class ExceptionDirWrapper;

class ExceptionDirWrapper : public DataDirEntryWrapper
{
public:
    ExceptionDirWrapper(PEFile* pe)
        : DataDirEntryWrapper(pe, pe::DIR_EXCEPTION), parsedSize(0) { wrap(); }

    bool wrap();

    virtual void* getPtr() { return exceptFunc64(); }
    virtual bufsize_t getSize() { return parsedSize; }

    virtual QString getName() { return "Exceptions Dir."; }
    virtual size_t getFieldsCount() { return entries.size(); }

    virtual void* getFieldPtr(size_t fieldId, size_t subField) { return getSubfieldPtr(fieldId, subField); }
    virtual QString getFieldName(size_t fieldId) { return "Exceptions Block"; }
    virtual QString getFieldName(size_t fieldId, size_t subField) { return getSubfieldName(fieldId, subField); }

protected:
    IMAGE_IA64_RUNTIME_FUNCTION_ENTRY* exceptFunc64();

private:
    static uint64_t EntriesLimit;

    bufsize_t parsedSize;

friend class ExceptionEntryWrapper;
};


class ExceptionEntryWrapper : public ExeNodeWrapper
{
public:
    // fields :
    enum ExceptionBlockFID {
        NONE = FIELD_NONE,
        BEGIN_ADDR,
        END_ADDR,
        UNWIND_INFO_ADDR,
        FIELD_COUNTER
    };

    ExceptionEntryWrapper(Executable *pe, ExceptionDirWrapper *parentDir, size_t entryNumber)
        : ExeNodeWrapper(pe, parentDir, entryNumber), cachedRaw(INVALID_ADDR) { this->parentDir = parentDir;}

    bool wrap() { return true; }

    // full structure boundatries
    virtual void* getPtr();

    virtual bufsize_t getSize();
    virtual QString getName() { return "Exceptions Block"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundatries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField);

private:
    offset_t cachedRaw;
    ExceptionDirWrapper* parentDir;
};

