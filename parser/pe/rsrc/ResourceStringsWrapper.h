#pragma once
#include "../ResourceLeafWrapper.h"
#include "ResourceContentWrapper.h"

#include <vector>

class ResString : public ExeNodeWrapper {
public:
    enum ResourceFID {
        NONE = FIELD_NONE,
        STR_LEN,
        WSTRING,
        FIELD_COUNTER
    };

    ResString(WORD *v_ptr, WORD *v_sizePtr, offset_t v_offset, Executable* v_exe)
        : ExeNodeWrapper(v_exe), ptr(v_ptr), sizePtr(v_sizePtr), offset(v_offset) { }

    /* full structure boundatries */
    virtual void* getPtr();
    virtual bufsize_t getSize();
    virtual QString getName();
    virtual size_t getFieldsCount() { return FIELD_COUNTER; }
    virtual size_t getSubFieldsCount() { return 1; }

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual QString getFieldName(size_t fieldId);
    virtual bufsize_t getFieldSize(size_t fId, size_t subField);

    QString getQString()
    {
        if (this->m_Exe == NULL) return ""; //ERROR
        WORD* entries = ptr;
        int size = *(sizePtr);
        WORD *content = (WORD*) this->m_Exe->getContentAt(offset,Executable::RAW, size);
        if (content == NULL) return "";

        return QString::fromUtf16(content, size);
    }

    virtual size_t getStrLen() { return (sizePtr == NULL) ? 0 : static_cast<size_t>(*sizePtr); }
    virtual WrappedValue::data_type containsDataType(size_t fieldId, size_t subField)
    {
        if (fieldId == WSTRING) {
            return WrappedValue::WSTRING;
        }
        return WrappedValue::INT;
    }
    WORD *ptr;
    WORD *sizePtr;
    offset_t offset;
};

class ResourceStringsWrapper : public ResourceContentWrapper
{
public:
    enum ResourceFID {
        NONE = FIELD_NONE,
        STR_LEN,
        WSTRING,
        FIELD_COUNTER
    };

    /* specific field boundatries */
    virtual QString getFieldName(size_t fieldId);
    virtual void* getFieldPtr(size_t fieldId, size_t subField);
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE);

    virtual size_t getFieldsCount()  { return entries.size(); }

    ResString* getResStringAt(size_t index)
    {
        if (index > entries.size()) return NULL;
        ResString* str = dynamic_cast<ResString*>(entries[index]);
        return str;
    }

    QString getQStringAt(size_t index)
    {
        ResString* str = getResStringAt(index);
        return str->getQString();
    }

    size_t getResStringsCount() { return entries.size(); }
    
    virtual WrappedValue::data_type containsDataType(size_t fieldId, size_t subField)
    {
        if (fieldId == WSTRING) {
            return WrappedValue::WSTRING;
        }
        return WrappedValue::INT;
    }

protected:
    static size_t EntriesLimit;

    ResourceStringsWrapper(Executable *pe, ResourceLeafWrapper* v_leaf)
        : ResourceContentWrapper(pe, v_leaf, pe::RT_STRING) { wrap(); }

    bool wrap();

    size_t parsedSize;

friend class ResourceContentFactory;
friend class ResourcesAlbum;
};

