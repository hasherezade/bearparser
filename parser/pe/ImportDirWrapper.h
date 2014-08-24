#pragma once

#include "ImportBaseDirWrapper.h"
#include "pe_formats.h"

/*
typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;    // PBYTE
        DWORD Function;        // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA32;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;    // PBYTE
        ULONGLONG Function;        // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    //PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
*/

class ImportDirWrapper;
class ImportEntryWrapper;
class ImportedFuncWrapper;

class ImportDirWrapper : public ImportBaseDirWrapper
{
public:
    ImportDirWrapper(Executable *pe)
        : ImportBaseDirWrapper(pe, pe::DIR_IMPORT) { wrap(); }

    bool wrap();
    virtual void* getPtr() { return firstDescriptor(); }
    virtual bufsize_t getSize();
    virtual QString getName() { return "Imports"; }

protected:
    pe::IMAGE_DATA_DIRECTORY* getDataDirectory();
    pe::IMAGE_IMPORT_DESCRIPTOR *firstDescriptor();

friend class ImportEntryWrapper;
};


class ImportEntryWrapper : public ImportBaseEntryWrapper
{
public:
    /* fields :*/
    enum FieldID {
        NONE = FIELD_NONE,
        ORIG_FIRST_THUNK,
        TIMESTAMP,
        FORWARDER,
        NAME,
        FIRST_THUNK,
        FIELD_COUNTER
    };

    ImportEntryWrapper(Executable *pe, ImportDirWrapper *importsDir, uint32_t entryNumber)
        : ImportBaseEntryWrapper(pe, importsDir, entryNumber) { wrap(); }

    bool wrap();
    bool isValid();

    /* full structure boundatries */
    virtual void* getPtr();

    virtual bufsize_t getSize();
    bool isBound();
    virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    char* getLibraryName();

friend class ImportDirWrapper;
};

class ImportedFuncWrapper : public ImportBaseFuncWrapper
{
public:
    /* fields :*/
    enum FieldID {
        NONE = FIELD_NONE,
        ORIG_THUNK,
        THUNK,
        FORWARDER,
        HINT,
        FIELD_COUNTER
    };

    ImportedFuncWrapper(Executable *pe, ImportEntryWrapper* parentLib, uint32_t entryNumber)
        : ImportBaseFuncWrapper(pe, parentLib, entryNumber) {}// this->parentLib = parentLib; }

    /* full structure boundatries */
    virtual void* getPtr();
    virtual pe::IMAGE_IMPORT_BY_NAME* getImportByNamePtr();

    virtual bufsize_t getSize();
    //virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    uint64_t getThunkValue();

    uint64_t getFieldRVA(ImportEntryWrapper::FieldID fId);
    void* getValuePtr(ImportEntryWrapper::FieldID fId);

    virtual uint64_t callVia() { return getFieldRVA(ImportEntryWrapper::FIRST_THUNK); }
    bool isByOrdinal();
    virtual uint64_t getOrdinal() { return getThunkValue(); }
    char* getFunctionName();

protected:
    void* getDataPtr(ImportEntryWrapper::FieldID fId);

friend class ImportDirWrapper;
};

