#pragma once

#include "DataDirEntryWrapper.h"
#include "pe_undoc.h"

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

protected:
    BYTE* getDebugStruct();
    pe::DEBUG_RSDSI* getRDSI();
    pe::DEBUG_NB10* getNB10();

    IMAGE_DEBUG_DIRECTORY* debugDir();

friend class DebugDirCVEntryWrapper;
};


class DebugDirCVEntryWrapper : public ExeNodeWrapper
{
public:
    // fields :
    enum FieldID {
        NONE = FIELD_NONE,
        F_CVDBG_SIGN,
        F_CVDBG_GUID,
        F_CVDBG_AGE,
        F_CVDBG_PDB,
        FIELD_COUNTER
    };

    DebugDirCVEntryWrapper(Executable* pe, DebugDirWrapper *_parentDir)
        : ExeNodeWrapper(pe, _parentDir, 0)
    {
        this->parentDir = _parentDir;
    }

    // full structure boundaries
    virtual void* getPtr();
    virtual bufsize_t getSize();

    virtual QString getName() { return "CodeView Info"; }
    virtual size_t getFieldsCount() { return getPtr() ? FIELD_COUNTER : 0; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundaries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField) { return Executable::NOT_ADDR; }

    //this wrapper only:
    QString getGuidString();
    QString getSignature();
private:
    DebugDirWrapper* parentDir;
};
