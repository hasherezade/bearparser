#pragma once

#include "DataDirEntryWrapper.h"
#include <set>

class ClrDirWrapper : public DataDirEntryWrapper
{
public:

    enum FieldID {
        NONE = FIELD_NONE,
        CB,
        MAJOR_RUNTIME_VER,
        MINOR_RUNTIME_VER,
        META_DATA_VA,
        META_DATA_SIZE,
        FLAGS,
        ENTRY_POINT,
        RESOURCES_VA,
        RESOURCES_SIZE,
        STRONG_NAME_SIGNATURE_VA,
        STRONG_NAME_SIGNATURE_SIZE,
        CODE_MANAGER_TABLE_VA,
        CODE_MANAGER_TABLE_SIZE,
        VTABLE_FIXUPS_VA,
        VTABLE_FIXUPS_SIZE,
        EXPORT_ADDR_TABLE_JMPS_VA,
        EXPORT_ADDR_TABLE_JMPS_SIZE,
        MANAGED_NATIVE_HDR_VA,
        MANAGED_NATIVE_HDR_SIZE,
        FIELD_COUNTER
    };

    static QString translateFlag(DWORD value);
    static std::set<DWORD> getFlagsSet(DWORD flags);
//---
    ClrDirWrapper(PEFile *pe)
        : DataDirEntryWrapper(pe, pe::DIR_COM_DESCRIPTOR) { wrap(); }

    ~ClrDirWrapper() { clear(); }

    bool wrap();

    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName();
    virtual size_t getFieldsCount();
    virtual size_t getSubFieldsCount() { return 1; }

    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE);
    
    QString translateFieldContent(size_t fieldId);
    
private:
    pe::IMAGE_COR20_HEADER* clrDir();

    void clear() {}
};

