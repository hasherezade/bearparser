#pragma once

#include "../ExeNodeWrapper.h"
#include "../Util.h"

class ImportBaseDirWrapper;
class ImportBaseEntryWrapper;
class ImportBaseFuncWrapper;

class ImportBaseDirWrapper : public ExeNodeWrapper
{
public:
    static uint64_t EntriesLimit;

    ImportBaseDirWrapper(Executable *pe)
        : ExeNodeWrapper(pe), importsCount(0) { wrap(); }

    virtual size_t getFieldsCount() { return this->importsCount; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField) { return getSubfieldPtr(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId, size_t subField) { return getSubfieldName(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId) { return getFieldName(fieldId, FIELD_NONE); }
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE) { return getSubfieldSize(fieldId, subField); }

    QString thunkToFuncName(offset_t thunk);

protected:
    void addFuncMapping(ImportBaseFuncWrapper *func);
    //---
    std::map<offset_t, size_t> thunkToLibMap;
    size_t importsCount;

friend class ImportBaseEntryWrapper;
};


class ImportBaseEntryWrapper : public ExeNodeWrapper
{
public:
    static uint64_t EntriesLimit;
    static uint32_t NameLenLimit;

    ImportBaseEntryWrapper(Executable *pe, ImportBaseDirWrapper *importsDir, uint32_t entryNumber)
        : ExeNodeWrapper(pe, importsDir, entryNumber), impDir(importsDir) { wrap(); }

    virtual char* getLibraryName() = 0;
    virtual size_t getSubFieldsCount() { return 1; }

protected:
    void addFuncMapping(ImportBaseFuncWrapper *func) { if (impDir) impDir->addFuncMapping(func); }
    std::map<offset_t, size_t> thunkToFuncMap;
    ImportBaseDirWrapper* impDir;

friend class ImportBaseDirWrapper;
};

class ImportBaseFuncWrapper : public ExeNodeWrapper
{
public:
    ImportBaseFuncWrapper(Executable *pe, ImportBaseEntryWrapper* parentLib, uint32_t entryNumber)
        : ExeNodeWrapper(pe, parentLib, entryNumber) { }

    virtual QString getName();

    virtual bool isByOrdinal() = 0;
    virtual uint64_t getOrdinal() = 0;
    virtual char* getFunctionName() = 0;

    virtual uint64_t callVia() = 0;

friend class ImportBaseDirWrapper;
};

