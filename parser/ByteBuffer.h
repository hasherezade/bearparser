#pragma once
#include "AbstractByteBuffer.h"

#define DEFAULT_PADDING 2

class ByteSubBuffer;

class ByteBuffer : public AbstractByteBuffer
{
public:
    ByteBuffer(bufsize_t v_size, bufsize_t padding = DEFAULT_PADDING);
    ByteBuffer(AbstractByteBuffer *sourceBuf, offset_t offset, bufsize_t size, bufsize_t padding = DEFAULT_PADDING);

    virtual ~ByteBuffer();

    virtual bufsize_t getContentSize() { return contentSize; }
    virtual BYTE* getContent() { return content; }

protected:
    BYTE* allocContent(bufsize_t v_size, bufsize_t padding);

    BYTE *content;
    bufsize_t contentSize;
    bufsize_t padding;
};


class ByteSubBuffer : public AbstractByteBuffer
{
public:
    ByteSubBuffer(AbstractByteBuffer *parent, offset_t offset, bufsize_t size);
    virtual ~ByteSubBuffer() { }

    virtual bufsize_t getContentSize();
    virtual BYTE* getContent();

    bufsize_t getRequestedSize() const { return size; }

protected:
    AbstractByteBuffer *parent;
    offset_t offset;
    bufsize_t size;
};

