#include "ByteBuffer.h"

ByteBuffer::ByteBuffer(bufsize_t v_size, bufsize_t v_padding)
    : content(NULL), contentSize(v_size), padding(v_padding)
{
    if (v_size == 0) throw BufferException("Zero size requested");

    this->content =  allocContent(v_size, v_padding);
    this->contentSize = v_size;
}

ByteBuffer::ByteBuffer(AbstractByteBuffer *v_parent, offset_t v_offset, bufsize_t v_size, bufsize_t v_padding)
{
    if (v_parent == NULL) throw BufferException("Cannot make subBuffer for NULL buffer!");

    if (v_size == 0) throw BufferException("Cannot make 0 size buffer!");

    BYTE *bContent = v_parent->getContentAt(v_offset, v_size);
    if (bContent == NULL) throw BufferException("Cannot make Buffer for NULL content!");

    this->content =  allocContent(v_size, v_padding);
    this->contentSize = v_size;

    memcpy(this->content, bContent, this->contentSize);
    TRACE();
}

BYTE* ByteBuffer::allocContent(bufsize_t v_size, bufsize_t v_padding)
{
    if (v_size == 0) throw BufferException("Zero size requested");

    BYTE* content =  (BYTE*) calloc(sizeof(BYTE), v_size + v_padding);
    if (content == NULL) throw BufferException("Cannot allocate buffer");

    return content;
}

ByteBuffer::~ByteBuffer()
{
    free(this->content);
    TRACE();
}

//--------------------------------------------

ByteSubBuffer::ByteSubBuffer(AbstractByteBuffer *v_parent, offset_t v_offset, bufsize_t v_size)
    : parent(v_parent), offset(v_offset), size(v_size)
{
    if (v_parent == NULL) throw BufferException("Cannot make subBuffer for NULL buffer!");
}

bufsize_t ByteSubBuffer::getContentSize()
{
    bufsize_t maxSize = this->parent->getContentSize();
    if (offset > maxSize) {
        return 0;
    }
    if (offset + size > maxSize) {
        bufsize_t trimedSize = maxSize - offset;
        return trimedSize;
    }
    return size;
}

BYTE* ByteSubBuffer::getContent()
{
    return this->parent->getContentAt(offset, getContentSize());
}

