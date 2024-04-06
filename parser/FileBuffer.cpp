#include "FileBuffer.h"


FileView::FileView(QString &path, bufsize_t maxSize)
    : AbstractFileBuffer(path), fIn (path)
{
    if (fIn.open(QIODevice::ReadOnly) == false) {
        throw FileBufferException("Cannot open the file: " + path);
    }
    this->fileSize = fIn.size();
    if (fileSize == 0) {
        std::cerr << fIn.errorString().toStdString() << std::endl;
        throw FileBufferException("The file is empty");
    }
    bufsize_t readableSize = getMappableSize(fIn);
    this->mappedSize = (readableSize > maxSize) ? maxSize : readableSize;

    uchar *pData = fIn.map(0, this->mappedSize);
    if (!pData) {
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

ByteBuffer* AbstractFileBuffer::read(QString &path, bufsize_t minBufSize, const bool allowTruncate)
{
    QFile fIn(path);
    if (fIn.open(QIODevice::ReadOnly) == false) {
        throw FileBufferException("Cannot open the file: " + path);
    }
    ByteBuffer *bufferedFile = read(fIn, minBufSize, allowTruncate);
    fIn.close();
    return bufferedFile;
}

ByteBuffer* AbstractFileBuffer::read(QFile &fIn, bufsize_t minBufSize, const bool allowTruncate) //throws exceptions
{
    bufsize_t readableSize = getReadableSize(fIn);
    bufsize_t allocSize = (readableSize < minBufSize) ? minBufSize : readableSize;

    ByteBuffer *bufferedFile = NULL;
    do {
        try {
            bufferedFile = new ByteBuffer(allocSize); //throws exceptions
        }
        catch (CustomException)
        {
            if (!allowTruncate) throw;
            allocSize /= 2;
        }
    } while(!bufferedFile && allocSize);

    char *content = (char*) bufferedFile->getContent();
    bufsize_t contentSize = bufferedFile->getContentSize();

    if (!content || !contentSize) throw FileBufferException("Cannot allocate buffer");
    //printf("Reading...%lx , BUFSIZE_MAX = %lx\n", allocSize, BUFSIZE_MAX);

    bufsize_t readSize = 0;
    offset_t prevOffset = 0;
    offset_t maxOffset = contentSize - 1;

    while (offset_t(fIn.pos()) < maxOffset) {

        bufsize_t maxSize = contentSize - readSize;
        if (maxSize > FILEVIEW_MAXSIZE) maxSize = FILEVIEW_MAXSIZE;

        readSize += fIn.read(content + readSize,  maxSize);
        if (prevOffset == fIn.pos()) break; //cannot read more!
        prevOffset = fIn.pos();
    }
    Logger::append(Logger::D_INFO,
        "Read size: %lX",
        static_cast<unsigned long>(readSize)
    );
    return bufferedFile;
}

bufsize_t AbstractFileBuffer::getReadableSize(QFile &fIn)
{
    qint64 fileSize = fIn.size();
    if (fileSize > qint64(FILE_MAXSIZE)) {
        fileSize = qint64(FILE_MAXSIZE);
    }
    return static_cast<bufsize_t>(fileSize);
}

bufsize_t AbstractFileBuffer::getReadableSize(const QString &path)
{
    if (!path.length()) return 0;
    QFile fIn(path);
    if (!fIn.open(QIODevice::ReadOnly)) return 0;
    const bufsize_t size = getReadableSize(fIn);
    fIn.close();
    return size;
}

bufsize_t AbstractFileBuffer::dump(const QString &path, AbstractByteBuffer &bBuf, bool allowExceptions)
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

