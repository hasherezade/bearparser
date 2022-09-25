#pragma once
#include <QtCore>

#include "ByteBuffer.h"

const bufsize_t FILE_MAXSIZE = BUFSIZE_MAX;
const bufsize_t FILEVIEW_MAXSIZE = (1024*1024*400); //419mb

class FileBufferException : public BufferException
{
public:
    FileBufferException(const QString info) : BufferException(info) {}
};


class AbstractFileBuffer {
public:
    static ByteBuffer* read(QString &file, bufsize_t minBufSize, const bool allowTruncate); //throws exceptions
    static bufsize_t getReadableSize(QFile &fIn);

    static bufsize_t getReadableSize(const QString &path);
    static bufsize_t dump(const QString &fileName, AbstractByteBuffer &buf, bool allowExceptions = false);
    QString getFileName() { return this->fileName; }

protected:
    static ByteBuffer* read(QFile &fIn, bufsize_t minBufSize, const bool allowTruncate); //throws exceptions

    AbstractFileBuffer(QString v_fileName) :fileName(v_fileName) {}

    QString fileName;
    qint64 fileSize; // real size of the file
};


class FileView : public AbstractByteBuffer, public AbstractFileBuffer
{
public:
    static bufsize_t getMappableSize(QFile &fIn);

    FileView(QString &fileName, bufsize_t maxSize = FILE_MAXSIZE); //throws exceptions
    virtual ~FileView();

    virtual bufsize_t getContentSize() { return mappedSize; }
    virtual BYTE* getContent() { return mappedContent; }
    bufsize_t getMappableSize() { return FileView::getMappableSize(fIn); }
    virtual bool isTruncated() { return fIn.size() > mappedSize; }

protected:
    BYTE *mappedContent;
    bufsize_t mappedSize;
    QFile fIn;
};


class FileBuffer : public AbstractByteBuffer, public AbstractFileBuffer
{
public:
    FileBuffer(QString &fileName, bufsize_t minSize, bool allowTruncate) //throws exceptions
        : AbstractFileBuffer(fileName)
    {
        QFile fIn(fileName);
        if (fIn.open(QFile::ReadOnly) == false) {
            throw FileBufferException("Cannot open the file: " + fileName);
        }
        fileSize = fIn.size();
        this->m_Buf = read(fIn, minSize, allowTruncate);//throws exceptions
        fIn.close();
    }

    virtual ~FileBuffer() { delete m_Buf; }

    virtual bufsize_t getContentSize() { return (m_Buf == NULL) ? 0 : m_Buf->getContentSize(); }
    virtual BYTE* getContent() { return (m_Buf == NULL) ? NULL : m_Buf->getContent(); }
    offset_t getFileSize() { return static_cast<offset_t>(fileSize); }
    bool resize(bufsize_t newSize) { return m_Buf->resize(newSize); }

    virtual bool isResized() { return m_Buf ? m_Buf->isResized() : false; }

    virtual bool isTruncated()
    {
        if (!m_Buf) return false;
        return fileSize > this->m_Buf->getContentSize();
    }

protected:
    ByteBuffer* m_Buf;
};
