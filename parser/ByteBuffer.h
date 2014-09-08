#pragma once
#include "AbstractByteBuffer.h"

#define DEFAULT_PADDING 2

class ByteBuffer : public AbstractByteBuffer
{
public:
    ByteBuffer(bufsize_t v_size, bufsize_t padding = DEFAULT_PADDING);
    ByteBuffer(AbstractByteBuffer *sourceBuf, offset_t offset, bufsize_t size, bufsize_t padding = DEFAULT_PADDING);

    virtual ~ByteBuffer();

    virtual bufsize_t getContentSize() { return contentSize; }
    virtual BYTE* getContent() { return content; }
    virtual bool resize(bufsize_t newSize); 
protected:
    BYTE* allocContent(bufsize_t v_size, bufsize_t padding);

    BYTE *content;
    bufsize_t contentSize;
    bufsize_t padding;
};

