#pragma once

#include "win_hdrs/win_types.h"
#include "ParserException.h"
#include "ByteBuffer.h"

#include <QtCore>

#include <iostream>
#include <string>
#include <string.h>
#include <stdlib.h>

#define INVALID_ADDR (-1)

#define UNIX_SEPARATOR '/'
#define WINDOWS_SEPARATOR '\\'

class AbstractFileBuffer : public AbstractByteBuffer
{
public:
    static char PATH_SEPARATOR;

    virtual QString getFullName() = 0;// file name (full, with directory path )
    virtual QString getShortName() = 0;// file name without path
    virtual QString getDir() = 0; // path to file

    virtual bufsize_t getFileSize() const = 0;
    virtual bufsize_t getOrigContentSize() const = 0;

    virtual bool dumpFragment(offset_t offset, bufsize_t size, QString path);

    bool isTruncated() { return (getFileSize() > static_cast<uint64_t>(getContentSize()) ); }
    bool isResized() { return (getContentSize() != getOrigContentSize()); }
    bool isShrinked() { return (getContentSize() < getOrigContentSize()); }
};

