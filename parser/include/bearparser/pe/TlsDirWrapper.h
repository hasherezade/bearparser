#pragma once

#include "DataDirEntryWrapper.h"
#include "PEFile.h"

class TlsEntryWrapper;
class TlsDirWrapper;

class TlsDirWrapper : public DataDirEntryWrapper
{
public:
        /* fields :*/
    enum TlsDirFID {
        NONE = FIELD_NONE,
        START_ADDR,
        END_ADDR,
        INDEX_ADDR,
        CALLBACKS_ADDR,
        ZEROF_SIZE,
        CHARACT,
        FIELD_COUNTER
    };

    TlsDirWrapper(PEFile *pe)
        : DataDirEntryWrapper(pe, pe::DIR_TLS) { wrap(); }

    bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();

    virtual QString getName() { return "TLS"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

private:
    static size_t EntriesLimit;

    inline void* getTlsDirPtr();
    IMAGE_TLS_DIRECTORY64* tls64();
    IMAGE_TLS_DIRECTORY32* tls32();
};


class TlsEntryWrapper : public ExeNodeWrapper
{
public:
    // fields :
    enum FieldID {
        NONE = FIELD_NONE,
        CALLBACK_ADDR,
        FIELD_COUNTER
    };

    TlsEntryWrapper(Executable *pe, TlsDirWrapper *parentDir, size_t entryNumber)
        : ExeNodeWrapper(pe, parentDir, entryNumber) { this->parentDir = parentDir; }

    // full structure boundaries
    virtual void* getPtr();
    virtual bufsize_t getSize();

    virtual QString getName() { return "TLS Callback"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundaries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE) { return getPtr();  }
    virtual QString getFieldName(size_t fieldId) { return getName(); }
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField) { return Executable::VA; }

private:
    TlsDirWrapper* parentDir;

};
