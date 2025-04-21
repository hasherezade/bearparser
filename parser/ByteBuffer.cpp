#include "ByteBuffer.h"
#include <iostream>
#include <limits.h>


void ByteBuffer::_init(const bufsize_t& v_size, const bufsize_t& v_padding)
{
    if (v_size == 0) throw BufferException("Zero size requested");

    this->content = allocContent(v_size, v_padding);
    if (this->content) {
        this->padding = v_padding;
        this->contentSize = v_size;
        this->originalSize = v_size;
    }
}

ByteBuffer::ByteBuffer(bufsize_t v_size, bufsize_t v_padding)
    : content(nullptr), contentSize(0), padding(0), originalSize(0)
{
    _init(v_size, v_padding);
}

ByteBuffer::ByteBuffer(BYTE* v_content, bufsize_t v_size, bufsize_t v_padding)
    : content(nullptr), contentSize(0), padding(0), originalSize(0)
{
    _init(v_size, v_padding);
    if (this->content && v_content) {
        ::memcpy(this->content, v_content, v_size);
    }
}

ByteBuffer::ByteBuffer(AbstractByteBuffer *v_parent, offset_t v_offset, bufsize_t v_size, bufsize_t v_padding)
    : content(nullptr), contentSize(0), padding(0), originalSize(0)
{
    if (!v_parent) throw BufferException("Cannot make subBuffer for NULL buffer!");
    if (!v_size) throw BufferException("Cannot make 0 size buffer!");

    bufsize_t parentSize = v_parent->getContentSize();

    bufsize_t copySize = v_size < parentSize ? v_size : parentSize;
    bufsize_t allocSize = v_size > parentSize ? v_size : parentSize;

    BYTE *bContent = v_parent->getContentAt(v_offset, copySize);
    if (!bContent) throw BufferException("Cannot make Buffer for NULL content!");

    _init(v_size, v_padding);
    if (this->content && bContent) {
        ::memcpy(this->content, bContent, v_size);
    }
}

BYTE* ByteBuffer::allocContent(bufsize_t v_size, bufsize_t v_padding)
{
    if (!v_size) throw BufferException("Zero size requested");
    if (v_size >= BUFSIZE_MAX || v_size >= LLONG_MAX) throw BufferException("Too big size requested");

    const bufsize_t allocSize = v_size + v_padding;
    const bufsize_t sizeDiff = (allocSize > this->contentSize) ? (allocSize - this->contentSize) : 0;

    BYTE* content = reinterpret_cast<BYTE*>(::realloc((void*)this->content, allocSize));
    if (!content) {
        throw BufferException("Cannot allocate buffer of size: 0x" + QString::number(allocSize, 16));
    }
    if (sizeDiff) {
        ::memset(content + this->contentSize, 0, sizeDiff);
    }
    return content;
}

bool ByteBuffer::resize(bufsize_t newSize)
{
    if (newSize == this->contentSize) {
        return true;
    }
    BYTE *newContent = nullptr;
    bool isOk = true;
    try {
        newContent = allocContent(newSize, this->padding);
        if (newContent) {
            this->content = newContent;
            this->contentSize = newSize;
        }
    } catch (const BufferException&) {
         isOk = false;
    }
    return isOk;
}

ByteBuffer::~ByteBuffer()
{
    ::free(this->content);
}
