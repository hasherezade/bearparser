#pragma once

#include "../ExeNodeWrapper.h"
#include "pe_formats.h"

class ExportDirWrapper : public ExeNodeWrapper
{
public:

    enum ExportDirFID {
        NONE = FIELD_NONE,
        CHARACTERISTIC,
        TIMESTAMP,
        MAJOR_VER,
        MINOR_VER,
        NAME_RVA,
        BASE,
        FUNCTIONS_NUM,
        NAMES_NUM,
        FUNCTIONS_RVA,
        FUNC_NAMES_RVA,
        NAMES_ORDINALS_RVA,
        FIELD_COUNTER
    };

    ExportDirWrapper(Executable *pe)
        : ExeNodeWrapper(pe) { wrap(); }

    bool wrap();

    virtual void* getPtr() { return exportDir(); }
    virtual bufsize_t getSize();
    virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);

    virtual char* getLibraryName();

    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

protected:
    void clear();
    size_t mapNames();

    pe::IMAGE_EXPORT_DIRECTORY* exportDir();
    std::map<WORD, DWORD> ordToNameId;

friend class ExportEntryWrapper;
};


class ExportEntryWrapper : public ExeNodeWrapper
{
public:
    // fields :
    enum FieldID {
        NONE = FIELD_NONE,
        FUNCTION_RVA,
        NAME_RVA,
        FIELD_COUNTER
    };

    ExportEntryWrapper(Executable *pe, ExportDirWrapper *parentDir, uint32_t entryNumber)
        : ExeNodeWrapper(pe, parentDir, entryNumber) { this->parentDir = parentDir; }

    // full structure boundatries
    virtual void* getPtr() { return getFuncRvaPtr(); }
    virtual bufsize_t getSize();
    virtual QString getName();

    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    // specific field boundatries
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);// { return getPtr();  }
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE) { return sizeof(DWORD);  }

    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField) { return Executable::RVA; }

    //DWORD getFuncRva();
    uint32_t getOrdinal();
    offset_t getFuncNameRva();

    void* getFuncRvaPtr();
    char* getFuncName();
    char* getForwarder(); // NULL if not forwarded

private:
    uint32_t getFuncNameId();
    void* getFuncNameRvaPtr();

    ExportDirWrapper* parentDir;
};

