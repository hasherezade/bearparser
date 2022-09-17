#pragma once

#include "DataDirEntryWrapper.h"
#include "../Util.h"

class ImportBaseDirWrapper;
class ImportBaseEntryWrapper;
class ImportBaseFuncWrapper;

namespace imports_util {
//    inline uint64_t getUpperLimit(Executable *pe, void* fieldPtr);
    inline bool isNameValid(Executable *pe, char* myName);
};

class ImportBaseDirWrapper : public DataDirEntryWrapper
{
public:
    static bufsize_t thunkSize(Executable::exe_bits bits);

    virtual bool wrap();
    virtual void clearMapping();
    virtual void reloadMapping();
    virtual size_t getFieldsCount() { return this->importsCount; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField) { return getSubfieldPtr(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId, size_t subField) { return getSubfieldName(fieldId, subField ); }
    virtual QString getFieldName(size_t fieldId) { return getFieldName(fieldId, FIELD_NONE); }
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE) { return getSubfieldSize(fieldId, subField); }

    QString thunkToFuncName(offset_t thunk, bool shortName=true);
    QString thunkToLibName(offset_t thunk);

    QList<offset_t> getThunksList() { return this->thunksList; }

    bool hasThunk(offset_t thunk) {
        std::map<offset_t, size_t>::iterator libItr = thunkToLibMap.find(thunk);
        return (libItr != thunkToLibMap.end());
    }

protected:
    ImportBaseDirWrapper(PEFile *pe, pe:: dir_entry v_entryType)
        : DataDirEntryWrapper(pe, v_entryType), importsCount(0) { }

    //virtual bool loadNextEntry(size_t entryNum) = 0;

    void addMapping(ExeNodeWrapper *func);
    ImportBaseEntryWrapper* thunkToLib(offset_t thunk);
    ImportBaseFuncWrapper* thunkToFunction(offset_t thunk);
    //---
    std::map<offset_t, size_t> thunkToLibMap;
    QList<offset_t> thunksList;

    size_t importsCount;

friend class ImportBaseEntryWrapper;
};


class ImportBaseEntryWrapper : public PENodeWrapper
{
public:
    static bufsize_t NameLenLimit;

    virtual char* getLibraryName() = 0;
    virtual size_t getSubFieldsCount() { return 1; }
    bool wrap();
    bool isValid();

protected:
    ImportBaseEntryWrapper(PEFile *pe, ImportBaseDirWrapper *importsDir, size_t entryNumber)
        : PENodeWrapper(pe, importsDir, entryNumber), impDir(importsDir) { }//wrap(); }

    void addMapping(ExeNodeWrapper *func) { if (impDir) impDir->addMapping(func); }

    std::map<offset_t, size_t> thunkToFuncMap;
    ImportBaseDirWrapper* impDir;

friend class ImportBaseDirWrapper;
};

class ImportBaseFuncWrapper : public PENodeWrapper
{
public:
    ImportBaseFuncWrapper(PEFile *pe, ImportBaseEntryWrapper* parentLib, size_t entryNumber)
        : PENodeWrapper(pe, parentLib, entryNumber) { }

    virtual QString getName();
    QString getShortName();

    virtual bool isByOrdinal() = 0;
    virtual uint64_t getOrdinal() = 0;
    virtual char* getFunctionName() = 0;

    virtual offset_t callVia() = 0;

    inline bufsize_t getAddrSize()
    { 
        size_t val = (isBit64()) ? sizeof(uint64_t) : sizeof(uint32_t);
        return static_cast<bufsize_t>(val);
    }
    
    inline bufsize_t getThunkValSize() { return getAddrSize(); }

friend class ImportBaseDirWrapper;
};

