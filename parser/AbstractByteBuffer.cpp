#include "AbstractByteBuffer.h"

bufsize_t buf_util::roundupToUnit(bufsize_t size, bufsize_t unit)
{   
    if (unit == 0) {
        printf("Invalid roundup unit!\n");
        return 0;
    }
    bufsize_t unitsNum = size / unit;
    bufsize_t roundDown = unitsNum * unit;
    if (roundDown < size) unitsNum ++;
    return unitsNum * unit;
}

//--------------------------------------------------
bool AbstractByteBuffer::isValid(AbstractByteBuffer *buf)
{
    if (buf == NULL) return false;
    if (buf->getContent() == NULL || buf->getContentSize() == 0) {
        return false;
    }
    return true;
}
//---

const BYTE AbstractByteBuffer::operator[](std::size_t idx)
{
    bufsize_t offset = static_cast<bufsize_t>(idx);
    if (offset >= getContentSize() ) {
        throw BufferException("Too far offset requested!");
    }
    return this->getContent()[idx];
}

offset_t AbstractByteBuffer::getOffset(BYTE *ptr,  bool allowExceptions)
{
    if (ptr == NULL) return INVALID_ADDR;
    BYTE* buf = this->getContent();
    bufsize_t bufSize = this->getContentSize();

    if (buf == NULL || bufSize == 0) {
        if (allowExceptions) throw BufferException("Buffer if empty!");
        return INVALID_ADDR;
    }
    if (ptr < buf) {
        if (allowExceptions) throw BufferException("Pointer before buffer begining!");
        return INVALID_ADDR;
    }
    offset_t offset = ptr - buf;
    if (offset >= bufSize) {
        if (allowExceptions) throw BufferException("Pointer does not belong to buffer!");
        return INVALID_ADDR;
    }
    return offset;
}

BYTE* AbstractByteBuffer::getContentAt(offset_t offset, bufsize_t size, bool allowExceptions)
{
    bufsize_t fileSize = this->getContentSize();
    BYTE* buf = this->getContent();
    if (buf == NULL) return NULL;

    if (offset >= fileSize ) {
        if (allowExceptions) throw BufferException("Too far offset requested!");
        return NULL;
    }

    if (offset + size > fileSize) {
        if (allowExceptions) throw BufferException("Too big size requested!");
        return NULL;
    }
    BYTE *cntnt = buf + offset;
    return cntnt;
}

BYTE* AbstractByteBuffer::getContentAtPtr(BYTE *ptr, bufsize_t size, bool allowExceptions)
{
    offset_t offset = getOffset(ptr, allowExceptions);
    if (offset == INVALID_ADDR) return NULL;

    return getContentAt(offset, size, allowExceptions);
}

bool AbstractByteBuffer::setBufferedValue(BYTE *dstPtr, BYTE *srcPtr, bufsize_t srcSize, bufsize_t paddingSize, bool allowExceptions)
{
    if (dstPtr == srcPtr) return false;
    if (dstPtr == NULL || srcPtr == NULL) return false;

    offset_t dstStart = getOffset(dstPtr);
    if (dstStart == INVALID_ADDR) {
        printf("Invalid copy destination!");
        if (allowExceptions) throw BufferException("Invalid copy destination!");
        return false;
    }

    bufsize_t size = srcSize + paddingSize;
    bufsize_t dstMaxSize = static_cast<bufsize_t>(getContentSize() - dstStart);
    if (dstMaxSize < size) {
        //throw BufferException("Cannot copy: too big content size!");
        size = dstMaxSize;
    }
    if (memcmp(dstPtr, srcPtr, size) == 0) {
        return false; //no changes required
    }
    if (paddingSize != 0) { //add padding
        memset(dstPtr, 0, size);
    }
    memcpy(dstPtr, srcPtr, srcSize);
    return true;
}

 bool AbstractByteBuffer::setStringValue(offset_t rawOffset, QString newText)
 {
     std::string newTextStr = newText.toStdString();

     BYTE *dstPtr = this->getContentAt(rawOffset, newTextStr.length() + 1);
     if (dstPtr == NULL) return false;
     
     const char* newTextC = newTextStr.c_str();
     bufsize_t newTextLen = static_cast<bufsize_t>(strlen(newTextC));
     bool isOk = setBufferedValue(dstPtr, (BYTE*)newTextC, newTextLen, 1);
     return isOk;
 }

bool AbstractByteBuffer::isAreaEmpty(offset_t rawOffset, bufsize_t size)
{
    BYTE * area = this->getContentAt(rawOffset, size);
    if (area == NULL) return false;

    for (bufsize_t i = 0; i < size; i++) {
        if (area[i] != 0) return false;
    }
    return true;
}

bool AbstractByteBuffer::fillContent(BYTE filling)
{
    bufsize_t bufSize = this->getContentSize();
    BYTE* buf = this->getContent();

    if (buf == NULL) return false;

    memset(buf, filling, bufSize);
    return true;
}

bool AbstractByteBuffer::pasteBuffer(offset_t rawOffset, AbstractByteBuffer *buf, bool allowTrunc)
{
    if (isValid(buf) == false || isValid(this) == false) return false;
    if (buf == NULL || buf->getContent() == NULL) return false;
    BYTE* source = buf->getContent();
    bufsize_t sizeToFill = buf->getContentSize();

    bufsize_t mySize = this->getContentSize();
    if (static_cast<offset_t>(mySize) <= rawOffset) {
        if (DBG_LVL) printf("Too far offset requested: %llX while mySize: %llX\n", rawOffset, mySize);
        return false;
    }
    BYTE *target = this->getContentAt(rawOffset, sizeToFill);
    if (target == NULL) {
        if (allowTrunc == false) return false;
        sizeToFill =  mySize - rawOffset;
        target = this->getContentAt(rawOffset, sizeToFill);
    }
    if (target == NULL) return false;
    memcpy(target, source, sizeToFill);
    return true;
}

 bool AbstractByteBuffer::containsBlock(offset_t rawOffset, bufsize_t size)
{
    if (rawOffset == INVALID_ADDR || size == 0) return false;

    BYTE *ptr = (BYTE*) this->getContent();
    if (ptr == NULL) return false;

    offset_t startOffset = this->getOffset(ptr);
    if (startOffset == INVALID_ADDR) return false;

    offset_t endOffset = startOffset + this->getContentSize();

    offset_t srchdEnd = rawOffset + size;
    if (rawOffset >= startOffset && srchdEnd <= endOffset) {
        //printf("Fount in bounds: %x - %x block: %x-%x\n", startOffset, endOffset, rawOffset, srchdEnd);
        return true;
    }
    return false;
}

bool AbstractByteBuffer::intersectsBlock(offset_t rawOffset, bufsize_t size)
{
    if (rawOffset == INVALID_ADDR || size == 0) return false;

    BYTE *ptr = (BYTE*) this->getContent();
    if (ptr == NULL) return false;

    offset_t startOffset = this->getOffset(ptr);
    if (startOffset == INVALID_ADDR) return false;

    offset_t endOffset = startOffset + this->getContentSize();

    offset_t srchdEnd = rawOffset + size;
    if (rawOffset >= startOffset && rawOffset <= endOffset) {
        //printf("Fount in bounds: %x - %x start: %x\n", startOffset, endOffset, rawOffset);
        return true;
    }
    if (srchdEnd >= startOffset && srchdEnd <= endOffset) {
        //printf("Fount in bounds: %x - %x end: %x\n", startOffset, endOffset, endOffset);
        return true;
    }
    return false;
}

uint64_t AbstractByteBuffer::getNumValue(offset_t offset, bufsize_t size, bool* isOk)
{
    if (isOk) (*isOk) = false;
    if (size == 0 || offset == INVALID_ADDR) return (-1);

    void* ptr = this->getContentAt(offset, size);
    if (ptr == NULL) {
        return (-1);
    }
    uint64_t val = (-1);

    if (size == sizeof(uint8_t)) val = *((uint8_t*) ptr);
    else if (size == sizeof(uint16_t)) val = *((uint16_t*) ptr);
    else if (size == sizeof(uint32_t)) val = *((uint32_t*) ptr);
    else if (size == sizeof(uint64_t)) val = *((uint64_t*) ptr);
    else {
        return (-1);
    }
    if (isOk) (*isOk) = true;
    return val;
}

bool AbstractByteBuffer::setNumValue(offset_t offset, bufsize_t size, uint64_t newVal)
{
    if (size == 0 || offset == INVALID_ADDR) return false;
    void* ptr = this->getContentAt(offset, size);
    if (ptr == NULL) {
        if (DBG_LVL) printf("Cannot get Ptr at: %llX of size: %lx!\n", offset, size);
        return false;
    }

    if (size == sizeof(uint8_t)) {
        uint8_t nVal = newVal;
        uint8_t* valPtr = (uint8_t*) ptr;
        if ((*valPtr) == nVal) return false;
        (*valPtr) = nVal;
    }
    else if (size == sizeof(uint16_t)) {
        uint16_t nVal = newVal;
        uint16_t* valPtr = (uint16_t*) ptr;
        if ((*valPtr) == nVal) return false;
        (*valPtr) = nVal;
    }
    else if (size == sizeof(uint32_t)) {
        uint32_t nVal = newVal;
        uint32_t* valPtr = (uint32_t*) ptr;
        if ((*valPtr) == nVal) return false;
        (*valPtr) = nVal;
    }
    else if (size == sizeof(uint64_t)) {
        uint64_t nVal = newVal;
        uint64_t* valPtr = (uint64_t*) ptr;
        if ((*valPtr) == nVal) return false;
        (*valPtr) = nVal;
    } else {
        if (DBG_LVL) printf("Wrong size!\n");
        return false;
    }
    return true;
}

//--------------------------------------------

BufferView::BufferView(AbstractByteBuffer *v_parent, offset_t v_offset, bufsize_t v_size)
    : parent(v_parent), offset(v_offset), size(v_size)
{
    if (v_parent == NULL) throw BufferException("Cannot make subBuffer for NULL buffer!");
}

bufsize_t BufferView::getContentSize()
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

BYTE* BufferView::getContent()
{
    return this->parent->getContentAt(offset, getContentSize());
}
