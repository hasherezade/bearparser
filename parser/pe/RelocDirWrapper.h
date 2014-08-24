#pragma once

#include "DataDirEntryWrapper.h"

class RelocEntryWrapper;
class RelocBlockWrapper;
class RelocDirWrapper;

class RelocDirWrapper : public DataDirEntryWrapper
{
public:
    RelocDirWrapper(Executable *pe)
        : DataDirEntryWrapper(pe, pe::DIR_BASERELOC), parsedSize(0) { wrap(); }

    bool wrap();

    virtual void* getPtr() { return reloc(); }

    virtual bufsize_t getSize() { return parsedSize; }
    virtual QString getName() { return "Relocation Dir."; }
    virtual size_t getFieldsCount() { return entries.size(); }

    virtual void* getFieldPtr(size_t fieldId, size_t subField) { return getSubfieldPtr(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId) { return "Relocation Block"; }
    virtual QString getFieldName(size_t fieldId, size_t subField) { return getSubfieldName(fieldId, subField ); }

protected:
    pe::IMAGE_BASE_RELOCATION* reloc();

private:
    static size_t EntriesLimit;

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
        : ExeNodeWrapper(pe, parentDir, entryNumber), cachedRaw(INVALID_ADDR), cachedMaxNum(-1) { this->parentDir = parentDir; wrap(); }

    bool wrap();

    // full structure boundatries
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "Relocation Block"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    // specific field boundatries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField);

    void* getEntriesPtr();
    size_t maxEntriesNumInBlock();

    pe::IMAGE_BASE_RELOCATION* myReloc() { return (pe::IMAGE_BASE_RELOCATION*) getPtr(); }

private:
    static size_t EntriesLimit;

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

    // full structure boundatries
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "Type-Offset"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundatries
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

