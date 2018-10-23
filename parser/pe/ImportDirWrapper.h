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
    ImportDirWrapper(PEFile *pe)
        : ImportBaseDirWrapper(pe, pe::DIR_IMPORT) { wrap(); }

    virtual void* getPtr() { return firstDescriptor(); }
    virtual bufsize_t getSize();
    virtual QString getName() { return "Imports"; }

protected:
    virtual bool loadNextEntry(size_t cntr);

    IMAGE_DATA_DIRECTORY* getDataDirectory();
    IMAGE_IMPORT_DESCRIPTOR *firstDescriptor();

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

    ImportEntryWrapper(PEFile *pe, ImportDirWrapper *importsDir, size_t entryNumber)
        : ImportBaseEntryWrapper(pe, importsDir, entryNumber) { wrap(); }

    //virtual bool wrap();
    //bool isValid();

    /* full structure boundaries */
    virtual void* getPtr();

    virtual bufsize_t getSize();
    bool isBound();
    virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }

    /* specific field boundaries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    bufsize_t geEntrySize()
    {
        if (m_Exe == NULL) return 0;
        return ImportBaseDirWrapper::thunkSize(m_Exe->getBitMode());
    }

    virtual offset_t getNextEntryOffset()
    {
         offset_t nextOffset = INVALID_ADDR;
        //get after existing entries:
        if (this->getEntriesCount() > 0) {
            return ExeNodeWrapper::getNextEntryOffset();
        }
        //get by thunk:
        IMAGE_IMPORT_DESCRIPTOR* desc = (IMAGE_IMPORT_DESCRIPTOR*) this->getPtr();
        if (!desc) return INVALID_ADDR;

        offset_t firstThunk = desc->FirstThunk;
        if (firstThunk == 0) {
            firstThunk = desc->OriginalFirstThunk;
        }
        nextOffset = m_Exe->convertAddr(desc->FirstThunk, Executable::RVA, Executable::RAW);
        return nextOffset;
    }

    char* getLibraryName();

protected:
     bool loadNextEntry(size_t entryNum);

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

    ImportedFuncWrapper(PEFile *pe, ImportEntryWrapper* parentLib, size_t entryNumber)
        : ImportBaseFuncWrapper(pe, parentLib, entryNumber) {}// this->parentLib = parentLib; }

    /* full structure boundaries */
    virtual void* getPtr();
    virtual IMAGE_IMPORT_BY_NAME* getImportByNamePtr();

    virtual bufsize_t getSize();
    //virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    /* specific field boundaries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField = FIELD_NONE);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);

    uint64_t getThunkValue();

    offset_t getFieldRVA(ImportEntryWrapper::FieldID fId);
    void* getValuePtr(ImportEntryWrapper::FieldID fId);

    virtual offset_t callVia() { return getFieldRVA(ImportEntryWrapper::FIRST_THUNK); }
    bool isByOrdinal();
    virtual uint64_t getOrdinal() { return getThunkValue(); }
    char* getFunctionName();

friend class ImportDirWrapper;
};

