#include "FileBuffer.h"

FileView::FileView(QString &path, bufsize_t maxSize)
    : AbstractFileBuffer(path), fIn (path)
{
    if (fIn.open(QFile::ReadOnly | QFile::Truncate) == false) {
        throw FileBufferException("Cannot open the file: " + path);
    }
    this->fileSize = fIn.size();
    //if (DBG_LVL) printf("File of size:\t%lld\n", fileSize);
    bufsize_t readableSize = getMappableSize(fIn);
    this->mappedSize = (readableSize > maxSize) ? maxSize : readableSize;
    //printf("Mapping size: %lx = %ld\n", this->mappedSize, this->mappedSize);
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

bufsize_t FileView::getMappableSize(QFile &fIn)
{
    bufsize_t size = getReadableSize(fIn);
    if (size > FILEVIEW_MAXSIZE) {
        size = FILEVIEW_MAXSIZE;
    }
    return size;
}
//----------------------------------------------------------------

ByteBuffer* AbstractFileBuffer::read(QString &path, bufsize_t minBufSize)
{
    //printf("reading file...");
    QFile fIn(path);
    if (fIn.open(QFile::ReadOnly | QFile::Truncate) == false) {
        throw FileBufferException("Cannot open the file: " + path);
    }
    ByteBuffer *bufferedFile = read(fIn, minBufSize);
    fIn.close();
    return bufferedFile;
}

ByteBuffer* AbstractFileBuffer::read(QFile &fIn, bufsize_t minBufSize) //throws exceptions
{
    bufsize_t readableSize = getReadableSize(fIn);
    bufsize_t allocSize = (readableSize < minBufSize) ? minBufSize : readableSize;
    //printf("Alloc size: %lx\n", allocSize);

    ByteBuffer *bufferedFile = new ByteBuffer(allocSize); //throws exceptions
    char *content = (char*) bufferedFile->getContent();
    bufsize_t contentSize = bufferedFile->getContentSize();

    if (content == NULL) throw FileBufferException("Cannot allocate buffer");
    //printf("Reading...%lx , BUFSIZE_MAX = %lx\n", allocSize, BUFSIZE_MAX);

    bufsize_t redSize = 0;
    offset_t prevOffset = 0;
    offset_t maxOffset = contentSize - 1;

    while (fIn.pos() < maxOffset) {

        bufsize_t maxSize = contentSize - redSize;
        if (maxSize > FILEVIEW_MAXSIZE) maxSize = FILEVIEW_MAXSIZE;

        redSize += fIn.read(content + redSize,  maxSize);
        if (prevOffset == fIn.pos()) break; //cannot read more!
        printf("redSize = %lx\n", redSize);
        prevOffset = fIn.pos();
    }
    //printf("Red size...%lx\n", redSize);
    return bufferedFile;
}

bufsize_t AbstractFileBuffer::getReadableSize(QFile &fIn)
{
    qint64 fileSize = fIn.size();
    bufsize_t size = static_cast<bufsize_t> (fileSize);

    if (size > FILE_MAXSIZE) {
        size = FILE_MAXSIZE;
    }
    return size;
}

bufsize_t AbstractFileBuffer::getReadableSize(QString &path)
{
    if (path.length() == 0) return 0;

    QFile fIn(path);
    if (fIn.open(QFile::ReadOnly | QFile::Truncate) == false) return 0;
    bufsize_t size = getReadableSize(fIn);
    fIn.close();
    return size;
}

bufsize_t AbstractFileBuffer::dump(QString path, AbstractByteBuffer &bBuf, bool allowExceptions)
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

