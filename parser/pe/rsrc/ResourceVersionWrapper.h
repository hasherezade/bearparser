#pragma once

#include "../ResourceLeafWrapper.h"
#include "ResourceContentWrapper.h"
#include "../pe_formats.h"

class ResourceVersionWrapper : public ResourceContentWrapper
{
public:
    enum ResourceFID {
        NONE = FIELD_NONE,
        STRUCT_LEN,
        VAL_LEN,
        STRUCT_TYPE,
        INFO,
        SIGNATURE,
        STRUCT_VER,
        FILE_VER_0,
        FILE_VER_1,
        PRODUCT_VER_0,
        PRODUCT_VER_1,
        FLAGS_MASK,
        FLAGS,
        OS,
        TYPE,
        SUBTYPE,
        TIMESTAMP_0,
        TIMESTAMP_1,
        CHILDREN,
        FIELD_COUNTER
    };

    ResourceVersionWrapper(Executable *pe, ResourceLeafWrapper* v_leaf);

    /* full structure boundatries */
    virtual void* getPtr() { return getVersionInfo(); }
    virtual bufsize_t getSize() { return (getVersionInfo() == NULL) ? 0 :sizeof(pe::version_info); }
    virtual QString getName() { return "Version"; }
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; } //TODO: children

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);

    virtual WrappedValue::data_type containsDataType(size_t fieldId, size_t subField = FIELD_NONE);

    pe::version_info *getVersionInfo();
    QString getVersionText()
    {
        pe::version_info *info = getVersionInfo();
        if (info == NULL) return ""; //ERROR

        int size = INFOTEXT_LEN;
        WORD *content = info->key;
        if (content == NULL) return "";

        return QString::fromUtf16(content, size);
    }



friend class ResourceContentFactory;
};

