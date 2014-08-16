#pragma once

#include "../ExeNodeWrapper.h"
#include "pe_formats.h"

class BoundImpDirWrapper : public ExeNodeWrapper
{
public:
    static uint64_t EntriesLimit;

    BoundImpDirWrapper(Executable *pe)
        : ExeNodeWrapper(pe), importsCount(0) { wrap(); }

    virtual bool wrap();

    virtual void* getPtr() { return boundImp(); }
    virtual bufsize_t getSize();
    virtual QString getName() { return "BoundImp"; }
    virtual size_t getFieldsCount() { return this->entries.size(); }

    virtual void* getFieldPtr(size_t fieldId, size_t subField) { return getSubfieldPtr(fieldId, subField ); }
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE) { return getSubfieldSize(fieldId, subField); }

    virtual QString getFieldName(size_t fieldId, size_t subField) { return getSubfieldName(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId) { return getFieldName(fieldId, FIELD_NONE); }

protected:
    pe::IMAGE_BOUND_IMPORT_DESCRIPTOR* boundImp();
    uint64_t importsCount;

friend class BoundEntryWrapper;
};

class BoundEntryWrapper : public ExeNodeWrapper
{
public:
    enum FieldID {
        NONE = FIELD_NONE,
        TIMESTAMP,
        MODULE_NAME_OFFSET,
        MODULE_FORWARDERS_NUM,
        FIELD_COUNTER
    };

    BoundEntryWrapper(Executable *pe, BoundImpDirWrapper* parent, uint32_t entryNum)
        : ExeNodeWrapper(pe, parent, entryNum ) { }

    bool wrap() { return true; }

    virtual void* getPtr();
    virtual  bufsize_t getSize();
    virtual QString getName();
    virtual char* getLibraryName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
};

