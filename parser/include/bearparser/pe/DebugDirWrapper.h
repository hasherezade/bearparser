#pragma once

#include "DataDirEntryWrapper.h"
#include "pe_undoc.h"


class DebugDirWrapper : public DataDirEntryWrapper
{
public:
    DebugDirWrapper(PEFile *pe)
        : DataDirEntryWrapper(pe, pe::DIR_DEBUG) { wrap(); }

    virtual void* getPtr() { return getDebugDir(); }
    
    virtual bufsize_t getSize()
    {
        return getDirEntrySize();
    }
    
    virtual QString getName() { return "Debug"; }
    
    virtual size_t getFieldsCount()
    {
        return entries.size();
    }

    virtual void* getFieldPtr(size_t fieldId, size_t subField) { return getSubfieldPtr(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId, size_t subField) { return getSubfieldName(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId) { return getFieldName(fieldId, FIELD_NONE); }
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE) { return getSubfieldSize(fieldId, subField); }
    
protected:
    bool wrap()
    {
        clear();
        if (!getDataDirectory()) {
            return false;
        }
        const size_t LIMIT = (-1);
        size_t cntr = 0;
        for (cntr = 0; cntr < LIMIT; cntr++) {
            if (loadNextEntry(cntr) == false) break;
        }
        return true;
    }

    virtual bool loadNextEntry(const size_t cntr);

    IMAGE_DEBUG_DIRECTORY* getDebugDir(size_t index = 0)
    {
        const offset_t rva = getDirEntryAddress();
        if (rva == INVALID_ADDR) {
            return NULL;
        }
        const size_t offset = index * sizeof(IMAGE_DEBUG_DIRECTORY);
        return (IMAGE_DEBUG_DIRECTORY*) m_Exe->getContentAt((rva + offset), Executable::RVA, sizeof(IMAGE_DEBUG_DIRECTORY));
    }

friend class DebugDirEntryWrapper;
};


class DebugDirEntryWrapper : public PENodeWrapper
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

    DebugDirEntryWrapper(PEFile *pe, DebugDirWrapper *rootDir, size_t entryNumber)
        : PENodeWrapper(pe, rootDir, entryNumber), dbgRootDir(rootDir)
    {
        wrap();
    }

    ~DebugDirEntryWrapper() { clear(); }

    bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();
    
    virtual QString getName()
    {
        IMAGE_DEBUG_DIRECTORY* d = debugDir();
        if (!d) return "";
        return translateType(d->Type);
    }
    
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    QString translateType(int type);
    QString translateFieldContent(size_t fieldId);

protected:
    
    IMAGE_DEBUG_DIRECTORY* debugDir()
    {
        if (!dbgRootDir) return NULL;
        return this->dbgRootDir->getDebugDir(this->entryNum);
    }
    
    BYTE* getDebugStruct();
    pe::DEBUG_RSDSI* getRDSI();
    pe::DEBUG_NB10* getNB10();

    DebugDirWrapper* dbgRootDir;

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

    DebugDirCVEntryWrapper(Executable* pe, DebugDirEntryWrapper *_parentDir)
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

    QString translateFieldContent(size_t fieldId);

    //this wrapper only:
    QString getGuidString();
    QString getSignature();
private:
    DebugDirEntryWrapper* parentDir;
};
