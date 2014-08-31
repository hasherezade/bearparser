#include "FileBuffer.h"

FileView::FileView(QString &path, bufsize_t maxSize)
    : fIn (path)
{
    if (fIn.open(QFile::ReadOnly | QFile::Truncate) == false) {
        throw FileBufferException("Cannot open the file: " + path);
    }
    this->fileSize = fIn.size();
    if (DBG_LVL) printf("File of size:\t%lld\n", fileSize);
    bufsize_t readableSize = getReadableSize(fIn);
    this->mappedSize = (readableSize > maxSize) ? maxSize : readableSize;

    uchar *pData = fIn.map(0, this->mappedSize);
    if (pData == NULL) {
        throw BufferException("Cannot map the file: " + path + " of size: 0x" + QString::number(this->mappedSize, 16));
    }
    this->mappedContent = (BYTE*) pData;
}

FileView::~FileView()
{
    fIn.unmap((uchar*)this->mappedContent);
    fIn.close();
}
//----------------------------------------------------------------

ByteBuffer* FileBuffer::read(QString &path, bufsize_t minBufSize)
{
    FileView fileMap(path);
    bufsize_t readableSize = fileMap.getContentSize();

    bufsize_t allocSize = (readableSize < minBufSize) ? minBufSize : readableSize;

    ByteBuffer *bufferefdFile = new ByteBuffer(&fileMap, 0, allocSize);
    return bufferefdFile;
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

