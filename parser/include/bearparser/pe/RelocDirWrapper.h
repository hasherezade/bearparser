#pragma once

#include "DataDirEntryWrapper.h"

class RelocEntryWrapper;
class RelocBlockWrapper;
class RelocDirWrapper;

class RelocDirWrapper : public DataDirEntryWrapper
{
public:
    RelocDirWrapper(PEFile *pe)
        : DataDirEntryWrapper(pe, pe::DIR_BASERELOC), parsedSize(0) { wrap(); }

    bool wrap();

    virtual void* getPtr() { return reloc(); }

    virtual bufsize_t getSize() { return parsedSize; }
    virtual QString getName() { return "Relocation Dir."; }
    virtual size_t getFieldsCount() { return entries.size(); }

    virtual void* getFieldPtr(size_t fieldId, size_t subField) { return getSubfieldPtr(fieldId, subField ); }
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField) { return getSubfieldSize(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId) { return "Relocation Block"; }
    virtual QString getFieldName(size_t fieldId, size_t subField) { return getSubfieldName(fieldId, subField ); }

protected:
    IMAGE_BASE_RELOCATION* reloc();

private:
    bufsize_t parsedSize;

friend class RelocBlockWrapper;
};


class RelocBlockWrapper : public ExeNodeWrapper
{
public:
    // fields :
    enum RelocBlockFID {
        NONE = FIELD_NONE,
        PAGE_VA,
        BLOCK_SIZE,
        ENTRIES_PTR,
        FIELD_COUNTER
    };

    RelocBlockWrapper(Executable *pe, RelocDirWrapper *parentDir, size_t entryNumber)
        : ExeNodeWrapper(pe, parentDir, entryNumber), cachedRaw(INVALID_ADDR), cachedMaxNum(0) { this->parentDir = parentDir; wrap(); }

    bool wrap();

    // full structure boundaries
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "Relocation Block"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    // specific field boundaries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField);
    virtual WrappedValue::data_type containsDataType(size_t fieldId, size_t subField);

    void* getEntriesPtr();
    size_t maxEntriesNumInBlock();

    IMAGE_BASE_RELOCATION* myReloc() { return (IMAGE_BASE_RELOCATION*) getPtr(); }

private:
    offset_t cachedRaw;
    //size_t cachedSize; // TODO
    offset_t cachedMaxNum;

    RelocDirWrapper* parentDir;

    size_t parsedSize;
};

class RelocEntryWrapper : public ExeNodeWrapper
{
public:
    // fields :
    enum FieldID {
        NONE = FIELD_NONE,
        RELOC_ENTRY_VAL,
        FIELD_COUNTER
    };

    RelocEntryWrapper(Executable* pe, RelocBlockWrapper *parentDir, size_t entryNumber)
        : ExeNodeWrapper(pe, parentDir, entryNumber) { this->parentDir = parentDir; }

    // full structure boundaries
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "Type-Offset"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundaries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE) { return getPtr();  }
    virtual QString getFieldName(size_t fieldId) { return getName(); }
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField) { return Executable::NOT_ADDR; }

    offset_t deltaToRVA(WORD delta);
    static WORD getType(WORD relocEntryVal);
    static WORD getDelta(WORD relocEntryVal);
    static QString translateType(WORD type);

private:
    RelocBlockWrapper* parentDir;
};

