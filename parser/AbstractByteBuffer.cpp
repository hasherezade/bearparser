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

BYTE AbstractByteBuffer::operator[](std::size_t idx)
{
    bufsize_t offset = static_cast<bufsize_t>(idx);
    if (offset >= getContentSize() ) {
        throw BufferException("Too far offset requested!");
    }
    return this->getContent()[idx];
}

offset_t AbstractByteBuffer::getOffset(void *ptr,  bool allowExceptions)
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
    offset_t offset = static_cast<BYTE*>(ptr) - buf;
    if (offset >= bufSize) {
        if (allowExceptions) throw BufferException("Pointer does not belong to buffer!");
        return INVALID_ADDR;
    }
    return offset;
}

BYTE* AbstractByteBuffer::getContentAt(offset_t offset, bufsize_t size, bool allowExceptions)
{
    if (offset == INVALID_ADDR) {
        if (allowExceptions) throw BufferException("Invalid address requested!");
        return NULL;
    }
    if (size == 0) {
        if (allowExceptions) throw BufferException("Zero size requested!");
        return NULL;
    }

    offset_t fileSize = this->getContentSize();
    BYTE* buf = this->getContent();
    if (buf == NULL) return NULL;

    if (offset >= fileSize ) {
        if (allowExceptions) throw BufferException("Too far offset requested! Buffer size: "
            + QString::number(fileSize) + " vs reguested Offset: " + QString::number(offset));
        return NULL;
    }
    const offset_t endOffset = offset + size;
    if (endOffset > fileSize) {
        if (allowExceptions) throw BufferException("Too big size requested! Buffer size: "
            + QString::number(fileSize) + " vs end of the requested area: " + QString::number(endOffset));
        return NULL;
    }
    BYTE *cntnt = buf + offset;
    return cntnt;
}

bufsize_t AbstractByteBuffer::getMaxSizeFromOffset(offset_t startOffset)
{
    if (startOffset == INVALID_ADDR) return 0;

    offset_t contentSize = getContentSize();
    if (contentSize < startOffset) return 0;

    bufsize_t limit = static_cast<bufsize_t>(contentSize - startOffset);
    return limit;
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
     const bufsize_t newTextLen = static_cast<bufsize_t>(newTextStr.length());

     BYTE *dstPtr = this->getContentAt(rawOffset, newTextLen + 1); //with terminating '\0'
     if (!dstPtr) {
         // cannot get a suitable buffer for the string
         return false;
     }
     const char* newTextC = newTextStr.c_str();
     bool isOk = setBufferedValue(dstPtr, (BYTE*)newTextC, newTextLen, 1);
     return isOk;
}

QString AbstractByteBuffer::getStringValue(offset_t rawOffset, bufsize_t size)
{
    if (size == BUFSIZE_MAX) {
        size = this->getContentSize() - rawOffset;
    }
    char *ptr = (char*) getContentAt(rawOffset, size);
    if (!ptr) return "";
    size_t asciiLen = pe_util::getAsciiLen(ptr, size);

    return QString::fromUtf8(ptr, static_cast<int>(asciiLen));
}

QString AbstractByteBuffer::getWStringValue(offset_t rawOffset, bufsize_t len)
{
    const bufsize_t unitSize = sizeof(WORD);
    bufsize_t size = unitSize;
    if (len != BUFSIZE_MAX) {
        size = len * unitSize;
    }
    WORD* ptr = (WORD*) this->getContentAt(rawOffset, size);
    if (ptr == NULL) return "";
    return QString::fromUtf16(ptr, static_cast<int>(len));
}

QString AbstractByteBuffer::getWAsciiStringValue(offset_t rawOffset, bufsize_t len)
{
    const bufsize_t unitSize = sizeof(WORD);
    bufsize_t size = unitSize;
    if (len != BUFSIZE_MAX && len != -1) {
        size = len * unitSize;
    }
    WORD* ptr = (WORD*) getContentAt(rawOffset, size);
    if (!ptr) return "";

    size_t asciiLen = pe_util::getAsciiLenW(ptr, len);
    return QString::fromUtf16(ptr, static_cast<int>(asciiLen));
}

bool AbstractByteBuffer::isAreaEmpty(offset_t rawOffset, bufsize_t size)
{
    BYTE* area = this->getContentAt(rawOffset, size);
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
        Logger::append(Logger::D_ERROR,
            "Too far offset requested: %llX while mySize: %lX", 
            static_cast<unsigned long long>(rawOffset), 
            static_cast<unsigned long>(mySize)
        );
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
        Logger::append(Logger::D_INFO,
            "Found in bounds: %llX - %llX end: %llX", 
            static_cast<unsigned long long>(startOffset),
            static_cast<unsigned long long>(endOffset),
            static_cast<unsigned long long>(rawOffset)
        );
        return true;
    }
    if (srchdEnd >= startOffset && srchdEnd <= endOffset) {
        Logger::append(Logger::D_INFO,
            "Found in bounds: %llX - %llX",
            static_cast<unsigned long long>(startOffset),
            static_cast<unsigned long long>(endOffset)
        );
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
        Logger::append(Logger::D_ERROR,
            "Cannot get Ptr at: %llX of size: %lX!", 
            static_cast<unsigned long long>(offset), 
            static_cast<unsigned long>(size)
        );
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
        Logger::append(Logger::D_ERROR, "Wrong size!");
        return false;
    }
    return true;
}

bool AbstractByteBuffer::setTextValue(char* textPtr, std::string newText, size_t fieldLimitLen)
{
    if (!textPtr) return false;

    size_t newLen = newText.length() + 1;
    offset_t textOffset = this->getOffset(textPtr);
    if (textOffset == INVALID_ADDR) {
        return false;
    }
    //check against the buffer overflow
    if (this->getOffset(textPtr + newLen) == INVALID_ADDR) {
        return false;
    }
    //if both strings are same, do not overwrite
    const char* newTextC = newText.c_str();
    if (!strcmp(newTextC, textPtr)) { //TODO: use a safe comparison
        return false;
    }
    //if the field size is set:
    if (fieldLimitLen != 0) {
        if (this->getOffset(textPtr + fieldLimitLen) == INVALID_ADDR) {
            return false;
        }
        //clear the previous field
        memset(textPtr, 0, fieldLimitLen);
        if (newLen > fieldLimitLen) newLen = fieldLimitLen;
    }
    memcpy(textPtr, newTextC, newLen);
    textPtr[newLen] = '\0';
    return true;
}

offset_t AbstractByteBuffer::substFragmentByFile(offset_t offset, bufsize_t contentSize, QFile &fIn)
{
    BYTE *contentPart = this->getContentAt(offset, contentSize);
    if (!contentPart) return 0; //invalid offset/size

    if (!fIn.isReadable()) return 0;

    size_t toLoad = fIn.size() < contentSize ? fIn.size() : contentSize;
    BYTE *fBuf = (BYTE*)::calloc(toLoad, 1);
    if (!fBuf) {
        return 0;
    }
    size_t loaded = fIn.read((char*)fBuf, toLoad);
    memset(contentPart, 0, contentSize);
    memcpy(contentPart, fBuf, loaded);
    free(fBuf); fBuf = NULL;

    return loaded;
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
