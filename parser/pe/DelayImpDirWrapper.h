#pragma once

#include "ImportBaseDirWrapper.h"
#include "pe_formats.h"

class DelayImpFuncWrapper;

class DelayImpDirWrapper : public ImportBaseDirWrapper
{
public:
    DelayImpDirWrapper(PEFile *pe)
        : ImportBaseDirWrapper(pe, pe::DIR_DELAY_IMPORT) { wrap(); }

    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName() { return "DelayImports"; }

protected:
    virtual bool loadNextEntry(size_t cntr);

    bool is64(); // autodetect! 64bit PE may use IMAGE_DELAY_LOAD32!
    bool is32() { return !is64(); }

    pe::IMAGE_DELAY_LOAD* firstDelayLd() { return (pe::IMAGE_DELAY_LOAD*) firstDelayLd(sizeof(pe::IMAGE_DELAY_LOAD)); }
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

    DelayImpEntryWrapper(PEFile *pe, DelayImpDirWrapper *importsDir, size_t entryNumber)
        : ImportBaseEntryWrapper(pe, importsDir, entryNumber) { wrap(); }

    //bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName();
    virtual char* getLibraryName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

protected:
    bool loadNextEntry(size_t entryNum);

    virtual IMAGE_IMPORT_BY_NAME* getFirstImpByNamePtr();

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

    DelayImpFuncWrapper(PEFile *pe, DelayImpEntryWrapper *parentDir, size_t entryNumber)
        : ImportBaseFuncWrapper(pe, parentDir, entryNumber) { this->parentDir = parentDir; }

    // full structure boundatries
    virtual void* getPtr() { return getFieldPtr(IAT_ADDR); }
    virtual bufsize_t getSize() { return sizeof(DWORD); }

    //virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundatries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField);

    char* getFunctionName();
    uint16_t getHint();
    bool isByOrdinal();
    virtual uint64_t getOrdinal();
    offset_t callVia();

private:
    size_t ptrLen() { return (m_Exe->getBitMode() == Executable::BITS_64) ?  sizeof(uint64_t) : sizeof(uint32_t); }
    virtual IMAGE_IMPORT_BY_NAME* getImportByNamePtr();
    DelayImpEntryWrapper* parentDir;
};
