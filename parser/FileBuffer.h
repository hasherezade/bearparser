#pragma once
#include <QtCore>

#include "ByteBuffer.h"

#define FILE_MAXSIZE BUFSIZE_MAX

class FileBufferException : public CustomException
{
public:
    FileBufferException(const QString info) : CustomException(info) {}
};


class FileBuffer{
public:
    static ByteBuffer* read(QString &file, bufsize_t minBufSize); //throws exceptions
    static bufsize_t getReadableSize(QFile &fIn);

    static bufsize_t getReadableSize(QString &path);
    static bufsize_t dump(QString fileName, AbstractByteBuffer &buf, bool allowExceptions = false);
//-----
};
