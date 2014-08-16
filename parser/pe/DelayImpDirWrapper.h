#pragma once

#include "ImportBaseDirWrapper.h"
#include "pe_formats.h"

class DelayImpFuncWrapper;

class DelayImpDirWrapper : public ImportBaseDirWrapper
{
public:
    static uint64_t EntriesLimit;

    DelayImpDirWrapper(Executable *pe)
        : ImportBaseDirWrapper(pe) { wrap(); }

    bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "DelayImports"; }

protected:
    pe::IMAGE_DELAY_LOAD32* firstDelayLd32() { return (pe::IMAGE_DELAY_LOAD32*) firstDelayLd(sizeof(pe::IMAGE_DELAY_LOAD32)); }
    pe::IMAGE_DELAY_LOAD64* firstDelayLd64() { return (pe::IMAGE_DELAY_LOAD64*) firstDelayLd(sizeof(pe::IMAGE_DELAY_LOAD64)); }
    void* firstDelayLd(bufsize_t size);
    bufsize_t getEntrySize();

friend class DelayImpEntryWrapper;
};

class DelayImpEntryWrapper : public ImportBaseEntryWrapper
{
public:
    enum DelayImpDirFID {
        NONE = FIELD_NONE,
        ATTRS,
        NAME,
        MOD,
        IAT,
        INT,
        BOUND_IAT,
        UNLOAD_IAT,
        TIMESTAMP,
        FIELD_COUNTER
    };

    DelayImpEntryWrapper(Executable *pe, DelayImpDirWrapper *importsDir, uint32_t entryNumber)
        : ImportBaseEntryWrapper(pe, importsDir, entryNumber) { wrap(); }
    bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName();
    virtual char* getLibraryName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

protected:
    static uint64_t entriesLimit;

    pe::IMAGE_DELAY_LOAD32* dl32();
    pe::IMAGE_DELAY_LOAD64* dl64();
    virtual pe::IMAGE_IMPORT_BY_NAME* getFirstImpByNamePtr();

friend class DelayImpFuncWrapper;
friend class DelayImpDirWrapper;
};

class DelayImpFuncWrapper : public ImportBaseFuncWrapper
{
public:
    // fields :
    enum FieldID {
        NONE = FIELD_NONE,
        NAMETHUNK_ADDR,
        IAT_ADDR,
        BOUND_IAT_ADDR,
        UNLOAD_IAT_ADDR,
        FIELD_COUNTER
    };

    DelayImpFuncWrapper(Executable *pe, DelayImpEntryWrapper *parentDir, uint32_t entryNumber)
        : ImportBaseFuncWrapper(pe, parentDir, entryNumber) { this->parentDir = parentDir; }

    // full structure boundatries
    virtual void* getPtr() { return getFieldPtr(IAT_ADDR); }
    virtual bufsize_t getSize() { return sizeof(DWORD); }

    //virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundatries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE) { return sizeof(DWORD); }
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField);

    char* getFunctionName();
    uint16_t getHint();
    bool isByOrdinal();
    virtual uint64_t getOrdinal();
    uint64_t callVia();

private:
    size_t ptrLen() { return (m_Exe->getBitMode() == Executable::BITS_64) ?  sizeof(uint64_t) : sizeof(uint32_t); }
    virtual pe::IMAGE_IMPORT_BY_NAME* getImportByNamePtr();
    DelayImpEntryWrapper* parentDir;
};

