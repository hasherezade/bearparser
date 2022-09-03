#pragma once

#include "win_hdrs/win_types.h"
#include "CustomException.h"
#include "AbstractByteBuffer.h"

#include <QtCore>

#include <iostream>
#include <stdlib.h>

class WrappedValue {
public:

    enum data_type {
        NONE = 0,
        INT,
        STRING,
        WSTRING,
        COMPLEX,
        DATATYPE_COUNT
    };

    WrappedValue()
        : m_Type(NONE), m_Owner(NULL), m_Offset(INVALID_ADDR), m_Size(0) {}

    WrappedValue(AbstractByteBuffer *owner, offset_t offset, bufsize_t size, data_type type)
        : m_Type(type), m_Owner(owner), m_Offset(offset), m_Size(size) {}

    data_type getDataType() { return m_Type; }
    QVariant getQVariant();
    QString toQString();
    bool isValid() { return (m_Size != 0); }
    
protected:
    virtual QString getIntFormat();

    data_type m_Type;
    AbstractByteBuffer* m_Owner;
    offset_t m_Offset;
    bufsize_t m_Size;
};
