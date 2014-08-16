#include "FileBuffer.h"

ByteBuffer* FileBuffer::read(QString &path, bufsize_t minBufSize)
{
    if (path.length() == 0) return NULL;

    QFile fIn(path);
    if (fIn.open(QFile::ReadOnly | QFile::Truncate) == false) {
        throw FileBufferException("Cannot open the file: " + path);
    }
    qint64 fileSize = fIn.size();
    if (DBG_LVL) printf("File of size:\t%lld\n", fileSize);

    bufsize_t size = getReadableSize(fIn);
    bufsize_t allocSize = size;
    if (allocSize < minBufSize) {
        allocSize = minBufSize;
    }
    ByteBuffer *buf = new ByteBuffer(allocSize);

    if (buf->getContentSize() != allocSize) {
        delete buf;
        buf = NULL;
        throw BufferException("Cannot allocate buffer for the file: " + path + " for reading");
    }

    BYTE* buffer = buf->getContent();

    uchar *pData = fIn.map(0, size);
    if (pData == NULL) {
        throw BufferException("Cannot map the file: " + path);
    }
    if (DBG_LVL) printf("Buffering size:\t%lld\n", size);
    memcpy(buffer, pData, size);
    fIn.unmap(pData);
    fIn.close();
    return buf;
}

bufsize_t FileBuffer::getReadableSize(QFile &fIn)
{
    qint64 fileSize = fIn.size();
    bufsize_t size = static_cast<bufsize_t> (fileSize);

    if (size > FILE_MAXSIZE) {
        size = FILE_MAXSIZE;
    }
    return size;
}

bufsize_t FileBuffer::getReadableSize(QString &path)
{
    if (path.length() == 0) return 0;

    QFile fIn(path);
    if (fIn.open(QFile::ReadOnly | QFile::Truncate) == false) return 0;
    bufsize_t size = getReadableSize(fIn);
    fIn.close();
    return size;
}

bufsize_t FileBuffer::dump(QString path, AbstractByteBuffer &bBuf, bool allowExceptions)
{
    BYTE* buf = bBuf.getContent();
    bufsize_t bufSize  = bBuf.getContentSize();
    if (buf == NULL) {
        if (allowExceptions) throw FileBufferException("Buffer is empty");
        return 0;
    }
    QFile fOut(path);
    if (fOut.open(QFile::WriteOnly) == false) {
        if (allowExceptions) throw FileBufferException("Cannot open the file: " + path + " for writing");
        return 0;
    }
    bufsize_t wrote = static_cast<bufsize_t> (fOut.write((char*)buf, bufSize));
    fOut.close();
    return wrote;
}

