#pragma once

#include "win_hdrs/win_types.h"
#include "CustomException.h"
#include "Util.h"

#include <QtCore>

#include <iostream>
#include <stdlib.h>

//------------------------------------------------

typedef uint32_t bufsize_t;
const bufsize_t BUFSIZE_MAX = bufsize_t(-1);

typedef uint64_t offset_t;
const offset_t INVALID_ADDR = offset_t(-1);
const offset_t  OFFSET_MAX = (INVALID_ADDR - 1);

class BufferException : public CustomException
{
public:
    BufferException(const QString info) : CustomException(info) {}
};

namespace buf_util {
    bufsize_t roundupToUnit(bufsize_t size, bufsize_t unit);
};

class AbstractByteBuffer
{
public:
    static bool isValid(AbstractByteBuffer *buf);

    AbstractByteBuffer() { }
    virtual ~AbstractByteBuffer() { }

    virtual bufsize_t getContentSize() = 0;
    virtual BYTE* getContent() = 0;
    virtual bool isTruncated() { return false; }

    BYTE operator[](size_t idx);

    virtual offset_t getOffset(void *ptr, bool allowExceptions = false); // validates
    virtual BYTE* getContentAt(offset_t offset, bufsize_t size, bool allowExceptions = false);
    virtual BYTE* getContentAtPtr(BYTE *ptr, bufsize_t size, bool allowExceptions = false);

    virtual bool setBufferedValue(BYTE *dstPtr, BYTE *srcPtr, bufsize_t srcSize, bufsize_t paddingSize, bool allowExceptions = false);
    bool setStringValue(offset_t rawOffset, QString newText);

    QString getStringValue(offset_t rawOffset, bufsize_t len = BUFSIZE_MAX);
    QString getWStringValue(offset_t rawOffset, bufsize_t len);
    QString getWAsciiStringValue(offset_t rawOffset, bufsize_t len);

    bufsize_t getMaxSizeFromOffset(offset_t startOffset);
    bufsize_t getMaxSizeFromPtr(BYTE *ptr) { return getMaxSizeFromOffset(getOffset(ptr)); }

    bool isAreaEmpty(offset_t rawOffset, bufsize_t size);
    bool fillContent(BYTE filling);
    bool pasteBuffer(offset_t rawOffset, AbstractByteBuffer *buf, bool allowTrunc);

    bool containsBlock(offset_t rawOffset, bufsize_t size);
    bool intersectsBlock(offset_t rawOffset, bufsize_t size);

    uint64_t getNumValue(offset_t offset, bufsize_t size, bool* isOk);
    bool setNumValue(offset_t offset, bufsize_t size, uint64_t newVal);
    virtual bool resize(bufsize_t newSize) { return false; }
};

//--------------------------------------------

class BufferView : public AbstractByteBuffer
{
public:
    BufferView(AbstractByteBuffer *parent, offset_t offset, bufsize_t size);
    virtual ~BufferView() { }

    virtual bufsize_t getContentSize();
    virtual BYTE* getContent();

    bufsize_t getRequestedSize() const { return size; }

protected:
    AbstractByteBuffer *parent;
    offset_t offset;
    bufsize_t size;
};


