#pragma once
#include <QtCore>

#include "ByteBuffer.h"

const bufsize_t FILE_MAXSIZE = BUFSIZE_MAX;
const bufsize_t FILEVIEW_MAXSIZE = (1024*1024*400); //419mb

class FileBufferException : public CustomException
{
public:
    FileBufferException(const QString info) : CustomException(info) {}
};


class AbstractFileBuffer {
public:
    static ByteBuffer* read(QString &file, bufsize_t minBufSize); //throws exceptions
    static bufsize_t getReadableSize(QFile &fIn);

    static bufsize_t getReadableSize(QString &path);
    static bufsize_t dump(QString fileName, AbstractByteBuffer &buf, bool allowExceptions = false);
    QString getFileName() { return this->fileName; }
protected:
    static ByteBuffer* read(QFile &fIn, bufsize_t minBufSize); //throws exceptions

    AbstractFileBuffer(QString v_fileName) :fileName(v_fileName) {}

    QString fileName;
    qint64 fileSize; // real size of the file
};


class FileView : public AbstractByteBuffer, public AbstractFileBuffer
{
public:
    FileView(QString &fileName, bufsize_t maxSize = FILE_MAXSIZE); //throws exceptions
    virtual ~FileView();

    virtual bufsize_t getContentSize() { return mappedSize; }
    virtual BYTE* getContent() { return mappedContent; }
    bufsize_t getMappableSize(QFile &fIn);

protected:
    BYTE *mappedContent;
    bufsize_t mappedSize;
    QFile fIn;
};


class FileBuffer : public AbstractByteBuffer, public AbstractFileBuffer
{
public:
    FileBuffer(QString &fileName, bufsize_t minSize, bufsize_t maxSize = FILE_MAXSIZE) //throws exceptions
        : AbstractFileBuffer(fileName)
    {
        QFile fIn(fileName);
        if (fIn.open(QFile::ReadOnly | QFile::Truncate) == false) {
            throw FileBufferException("Cannot open the file: " + fileName);
        }
        fileSize = fIn.size();
        this->m_Buf = read(fIn, minSize);//throws exceptions
        fIn.close();
    }

    virtual ~FileBuffer() { delete m_Buf; }

    virtual bufsize_t getContentSize() { return (m_Buf == NULL) ? 0 : m_Buf->getContentSize(); }
    virtual BYTE* getContent() { return (m_Buf == NULL) ? NULL : m_Buf->getContent(); }
    uint64_t getFileSize() { return static_cast<uint64_t>(fileSize); }

protected:
    ByteBuffer* m_Buf;
};