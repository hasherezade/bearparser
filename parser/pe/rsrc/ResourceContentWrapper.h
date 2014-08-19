#pragma once

#include "../../ExeElementWrapper.h"
#include "../ResourceLeafWrapper.h"
#include "../pe_formats.h"

class ResourceContentFactory;

class ResourceContentWrapper : public ExeNodeWrapper
{
public:
    static QString translateType(pe::resource_type type);

    virtual ~ResourceContentWrapper() {}

    void* getResContentPtr();
    bufsize_t getResContentSize();
    offset_t getContentRaw();

    pe::resource_type getType() { return typeId; }

    virtual void* getPtr() { return getResContentPtr(); }
    virtual bufsize_t getSize() { return getResContentSize(); }

    virtual QString getName() { return translateType(this->typeId); }
    virtual size_t getFieldsCount()  { return 1; }
    virtual size_t getSubFieldsCount()  { return 1; }

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField) { return getPtr(); }
    virtual QString getFieldName(size_t fieldId)  { return getName(); }
    virtual WrappedValue::data_type containsDataType(size_t fieldId, size_t subField = FIELD_NONE) { return WrappedValue::COMPLEX; }

protected:
    ResourceContentWrapper(Executable *pe, ResourceLeafWrapper* v_leaf, pe::resource_type v_typeId)
        : ExeNodeWrapper(pe), myLeaf(v_leaf),  typeId(v_typeId) {}

    BYTE* getContentAt(offset_t dataAddr, Executable::addr_type aT, bufsize_t dataSize);

    ResourceLeafWrapper* myLeaf;
    pe::resource_type typeId;

friend class ResourceContentFactory;
};


class ReourceManifestWrapper : public ResourceContentWrapper
{
public:
    virtual WrappedValue::data_type containsDataType(size_t fieldId, size_t subField = FIELD_NONE) { return WrappedValue::STRING; }

protected:
    ReourceManifestWrapper(Executable *pe, ResourceLeafWrapper* v_leaf)
        : ResourceContentWrapper(pe, v_leaf, pe::RT_MANIFEST) {}

friend class ResourceContentFactory;
};

class ReourceHTMLWrapper : public ResourceContentWrapper
{
public:
    virtual WrappedValue::data_type containsDataType(size_t fieldId, size_t subField = FIELD_NONE) { return WrappedValue::STRING; }

protected:
    ReourceHTMLWrapper(Executable *pe, ResourceLeafWrapper* v_leaf)
        : ResourceContentWrapper(pe, v_leaf, pe::RT_HTML
        ) {}

friend class ResourceContentFactory;
};