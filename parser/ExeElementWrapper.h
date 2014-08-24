#pragma once

#include <QtCore>
#include "CustomException.h"
#include "win_hdrs/win_types.h"
#include "Executable.h"
#include "WrappedValue.h"

#define FIELD_NONE (-1)

class ExeElementWrapper : public AbstractByteBuffer
{
public:
    ExeElementWrapper(Executable *exe);
    virtual ~ExeElementWrapper() {}

    virtual bool wrap() { return true; }

    /* inherited from: AbstractByteBuffer */
    virtual bufsize_t getContentSize() { return getSize(); }
    virtual BYTE* getContent() { return static_cast<BYTE*>(getPtr()); }

    /* full structure boundatries */
    virtual void* getPtr() = 0;
    virtual bufsize_t getSize() = 0;
    virtual QString getName() = 0;

    virtual size_t getFieldsCount() = 0;
    virtual size_t getSubFieldsCount() { return 1; }

    offset_t getOffset();
    offset_t getOffset(void *ptr);

    /* specific field boundatries */
    virtual void* getFieldPtr(size_t fieldId, size_t subField) = 0;
    void* getFieldPtr(size_t fieldId) { return getFieldPtr(fieldId, FIELD_NONE); }
    virtual bufsize_t getFieldSize(size_t fieldId, size_t subField = FIELD_NONE);
    virtual offset_t getFieldOffset(size_t fieldId, size_t subField = FIELD_NONE);

    virtual QString translateFieldContent(size_t fieldId) { return ""; }

    virtual QString getFieldName(size_t fieldId) = 0;
    virtual WrappedValue getWrappedValue(size_t fieldId, size_t subField);
    virtual WrappedValue getWrappedValue(size_t fieldId) { return getWrappedValue(fieldId, FIELD_NONE); }

    virtual Executable::addr_type containsAddrType(size_t fieldId, size_t subField = FIELD_NONE) { return Executable::NOT_ADDR; }
    virtual WrappedValue::data_type containsDataType(size_t fieldId, size_t subField = FIELD_NONE) { return WrappedValue::INT; }

    virtual uint64_t getNumValue(size_t fieldId, size_t subField, bool* isOk);
    uint64_t getNumValue(size_t  fieldId, bool* isOk) { return getNumValue(fieldId, FIELD_NONE, isOk); }

    virtual bool setNumValue(size_t fieldId, size_t subField, uint64_t val);
    bool setNumValue(size_t fieldId, uint64_t val) { return setNumValue(fieldId, FIELD_NONE, val); }
    bool setStringValue(char* textPtr, QString newTextVal);

    Executable* getExe() { return m_Exe; }

    inline bool isBit64() { return Executable::isBit32(m_Exe); }
    inline bool isBit32() { return Executable::isBit64(m_Exe); }

protected:
    virtual bool canCopyToOffset(offset_t rawOffset);
    bool copyToOffset(offset_t rawOffset);

    Executable *m_Exe;
};

